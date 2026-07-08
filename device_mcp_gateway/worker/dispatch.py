# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Tool-call consumption and dispatch for a DeviceWorker (SRE #1/#4/#5/#6, F-08, F-13).

Extracted from the DeviceWorker god-object. Holds the per-device consume loop,
two-level backpressure, XAUTOCLAIM recovery, the idempotency guard, dead-letter
publishing, and the core dispatch pipeline (decode → guard → pod call → result
marker → publish → audit).

The dispatcher deliberately holds a reference to its worker and reads shared
state (`_pods`, `_assigned`, `_backend`, semaphores, config scalars) at call
time rather than capturing it at construction: the worker's tests — and the
worker itself during startup — mutate those attributes directly (e.g. assigning
``worker._backend`` without calling ``run()``), and a snapshot would silently
diverge. ``DeviceWorker`` keeps thin ``_dispatch_call``-style delegating
wrappers so its private call surface is unchanged.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any

from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.audit import audit_log
from device_mcp_gateway.core.backoff import jittered
from device_mcp_gateway.core.errors import RPC_DUPLICATE, RPC_INTERNAL_ERROR, RPC_NO_WORKER, rpc_error
from device_mcp_gateway.observability import tracing
from device_mcp_gateway.pods.device_pod import DevicePod

if TYPE_CHECKING:  # pragma: no cover
    from device_mcp_gateway.worker.runner import DeviceWorker


def _runner_mod():
    """The runner module, resolved lazily.

    ``_DLQ_MAXLEN`` / ``_IDEMPOTENT_METHODS`` stay canonical on ``worker.runner``
    (tests monkeypatch them there by module attribute), so they must be read at
    call time from that module — a value captured at import would not see the
    patch. Lazy import also avoids a runner⇄dispatch import cycle.
    """
    from device_mcp_gateway.worker import runner

    return runner


def _decode_fields(fields: dict) -> dict:
    """Return stream-entry fields with str keys/values.

    Real Redis with decode_responses=True already yields str; fakeredis returns
    bytes for stream fields. Normalising here lets dispatch_call read fields the
    same way whether they came from XREADGROUP or XAUTOCLAIM, under either client.
    """
    out = {}
    for k, v in fields.items():
        out[k.decode() if isinstance(k, bytes) else k] = v.decode() if isinstance(v, bytes) else v
    return out


class CallDispatcher:
    """Consumes a device's call stream and executes tool calls on its pod."""

    def __init__(self, worker: "DeviceWorker") -> None:
        self._w = worker

    async def consume_calls(self, hostname: str) -> None:
        w = self._w
        stream = f"device:{hostname}:calls"
        group = f"workers-{hostname}"
        # Ensure consumer group for this device's call stream
        try:
            await w._r.xgroup_create(stream, group, id="0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                logger.warning(f"xgroup_create {stream}: {exc}")

        # Per-device concurrency cap (SRE #5). Awaiting this in the consume loop
        # applies backpressure: when slots are exhausted we stop reading new
        # entries, so they remain delivered-unacked (visible as stream lag) rather
        # than piling up as unbounded in-memory tasks.
        sem = asyncio.Semaphore(w._max_calls_per_device)

        while not w._stop_event.is_set() and hostname in w._assigned:
            try:
                # First, reclaim entries a previous owner (typically a dead worker)
                # delivered into the group's PEL but never acked, so in-flight calls
                # at crash time aren't stranded forever (SRE #1). Only entries idle
                # longer than _reclaim_min_idle_ms are taken, so this never steals a
                # call still running on a healthy owner.
                # NOTE: cross-method calls in this class go through the worker's
                # delegating wrappers (w._reclaim_pending, w._schedule_dispatch, …)
                # so an instance-level monkeypatch on the worker still intercepts
                # them — several tests patch e.g. ``worker._dispatch_call`` directly.
                await w._reclaim_pending(hostname, stream, group, sem)

                results = await w._r.xreadgroup(
                    group,
                    w._id,
                    {stream: ">"},
                    count=5,
                    block=2000,
                )
                if not results:
                    continue
                for _s, messages in results:
                    for msg_id, fields in messages:
                        await w._schedule_dispatch(sem, hostname, stream, group, msg_id, _decode_fields(fields))
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception(f"Call consumer error for {hostname}; retrying")
                await asyncio.sleep(jittered(1))  # F-61: de-sync reconnect storms

    async def schedule_dispatch(
        self, sem: asyncio.Semaphore, hostname: str, stream: str, group: str, msg_id: str, fields: dict
    ) -> None:
        """Acquire a per-device AND the worker-wide slot, then dispatch (SRE #5/#6, F-13).

        Two-level backpressure: ``sem`` bounds this one device's in-flight calls; the
        shared ``_worker_call_sem`` bounds the aggregate across every device the worker
        hosts. Both are acquired by the consume loop *before* the dispatch task is
        created, so when either is exhausted the loop stops reading new entries and the
        burst stays as delivered-unacked stream lag instead of unbounded tasks. The
        device slot is taken first so a device blocked on its own cap never holds a
        scarce worker-wide slot. The task is tracked in _inflight_calls so shutdown can
        drain it, and releases both slots when done.
        """
        w = self._w
        await sem.acquire()
        # A blocked worker-wide acquire is the worker-saturation signal (F-13).
        if w._worker_call_sem.locked():
            metrics.worker_calls_throttled_total.inc()
        try:
            await w._worker_call_sem.acquire()
        except BaseException:
            sem.release()  # never strand a device slot if the worker-wide wait is cancelled
            raise
        task = asyncio.create_task(w._dispatch_guarded(sem, hostname, stream, group, msg_id, fields))
        w._inflight_calls.add(task)
        task.add_done_callback(w._inflight_calls.discard)

    async def _dispatch_guarded(
        self, sem: asyncio.Semaphore, hostname: str, stream: str, group: str, msg_id: str, fields: dict
    ) -> None:
        try:
            await self._w._dispatch_call(hostname, stream, group, msg_id, fields)
        finally:
            self._w._worker_call_sem.release()
            sem.release()

    async def reclaim_pending(self, hostname: str, stream: str, group: str, sem: asyncio.Semaphore) -> None:
        """XAUTOCLAIM idle pending entries to this worker and dispatch them.

        Recovers tool calls a now-dead worker had read (moving them into its PEL)
        but never acked before crashing. The new owner — assigned by the
        reconciler (SRE #2) — runs this and picks the stranded calls up. Tolerant
        of XAUTOCLAIM being unavailable or transient errors: a reclaim hiccup must
        never break the consume loop.
        """
        w = self._w
        try:
            claimed = await w._r.xautoclaim(
                stream, group, w._id, min_idle_time=w._reclaim_min_idle_ms, start_id="0-0", count=10
            )
        except Exception as exc:
            logger.debug(f"xautoclaim {stream}: {exc}")
            return
        # redis-py returns (next_cursor, claimed_messages[, deleted_ids]).
        messages = claimed[1] if isinstance(claimed, (list, tuple)) and len(claimed) >= 2 else []
        for msg_id, fields in messages:
            mid = msg_id.decode() if isinstance(msg_id, bytes) else msg_id
            logger.info(f"Reclaimed stranded call {mid} for {hostname}")
            await w._schedule_dispatch(sem, hostname, stream, group, mid, _decode_fields(fields))

    async def dead_letter(self, hostname: str, fields: dict, reason: str) -> None:
        """Move an undeliverable tool call to the device's dead-letter stream (SRE #4).

        Bounded so it can't grow without limit. Failure to dead-letter is logged
        but never propagated — it must not break dispatch/ack.
        """
        try:
            payload = {k: str(v) for k, v in fields.items()}
            payload["reason"] = reason
            payload["ts"] = str(time.time())
            await self._w._r.xadd(
                f"device:{hostname}:calls:dead", payload, maxlen=_runner_mod()._DLQ_MAXLEN, approximate=True
            )
            metrics.dead_letter_total.labels(hostname=hostname).inc()
        except Exception:
            logger.exception(f"Failed to dead-letter call for {hostname}")

    # ------------------------------------------------------------------
    # Idempotency guard (F-08)
    # ------------------------------------------------------------------

    async def guard_duplicate(self, hostname: str, request_id: str, pod: DevicePod, message: dict) -> str | None:
        """Decide whether a (possibly redelivered) call should be (re-)executed.

        Returns None to proceed, or a reason string to suppress execution:
          - ``already_completed``: the result was already published (the original
            attempt finished but died before acking) — don't re-run or re-publish.
          - ``nonidempotent_guard``: a non-idempotent op had already begun and we
            can't prove it didn't apply — refuse rather than double-execute.

        The single-delivery happy path returns None (the markers don't yet exist),
        so this only ever suppresses a genuine duplicate/reclaim.
        """
        w = self._w
        if await w._already_completed(request_id):
            return "already_completed"
        if w._is_idempotent_call(pod, message):
            return None  # safe/idempotent method — re-running is harmless
        # Non-idempotent: claim the exclusive right to execute this request_id once.
        if await w._begin_exec(request_id):
            return None  # we are the first; proceed
        return "nonidempotent_guard"

    async def already_completed(self, request_id: str) -> bool:
        """True if a result was already recorded for this call (dedup fast path)."""
        return bool(await self._w._r.exists(f"result:{request_id}"))

    async def begin_exec(self, request_id: str) -> bool:
        """SET-NX a 'started' marker; True only for the first executor of this id.

        A subsequent reclaim of the same entry finds the marker set and refuses,
        so a non-idempotent operation runs at most once across the fleet.
        """
        w = self._w
        return bool(await w._r.set(f"exec:{request_id}", w._id, nx=True, ex=w._idempotency_ttl))

    def is_idempotent_call(self, pod: DevicePod, message: dict) -> bool:
        """True if re-executing this call carries no extra side effect.

        Read-only MCP methods (tools/list, resources/read, ping, …) are inherently
        safe. For tools/call, idempotency follows the backing HTTP method. An
        unknown tool name produces a handler-not-found error with no upstream call,
        so it's safe to re-run too.
        """
        if not isinstance(message, dict) or message.get("method") != "tools/call":
            return True
        params = message.get("params") or {}
        tool_name = params.get("name")
        for tool in pod.manifest.tools:
            if tool.name == tool_name:
                return tool.method.upper() in _runner_mod()._IDEMPOTENT_METHODS
        return True

    # ------------------------------------------------------------------
    # Core dispatch pipeline
    # ------------------------------------------------------------------

    async def dispatch_call(self, hostname: str, stream: str, group: str, msg_id: str, fields: dict) -> None:
        w = self._w
        session_id = fields.get("session_id", "")
        request_id = fields.get("request_id", "")
        # X-Request-Id from the gateway (SRE O2): bind it in the worker's audit log
        # so one trace id spans the gateway dispatch and the worker execution.
        rid = fields.get("rid", "-")
        # Authenticated principal that issued the call (F-30 residual): the gateway
        # authorized + logged it at the edge and rode the subject along the stream;
        # bind it here so the worker-side execution audit carries the same actor
        # attribution ("who called this tool"), not just the correlation id.
        subject = fields.get("subject") or "-"
        # Initialised before the try so the failure path below can dead-letter/notify
        # even if json.loads itself raises.
        message: Any = {}
        _method = "?"
        try:
            message = json.loads(fields.get("message", "{}"))
            _method = message.get("method", "?") if isinstance(message, dict) else "?"
            pod = w._pods.get(hostname)
            if pod is None:
                # No pod to serve this call (e.g. a pod-replace window). Dead-letter
                # it instead of dropping silently, and tell the client rather than
                # letting it hang to the F6 timeout (SRE #4).
                logger.warning(f"No pod for {hostname}; dead-lettering call {msg_id}")
                await w._dead_letter(hostname, fields, "no active pod")
                msg_id_val = message.get("id") if isinstance(message, dict) else None
                if session_id and msg_id_val is not None:
                    await w._session_router.publish_result(
                        session_id,
                        rpc_error(
                            RPC_NO_WORKER,
                            msg_id_val,
                            rid=rid,
                            request_id=request_id,
                            message=f"No active pod for {hostname}; call not served",
                        ),
                    )
                if request_id:
                    await w._r.set(f"result:{request_id}", "1", ex=w._result_marker_ttl)
                audit_log(
                    "tool dispatch",
                    hostname=hostname,
                    subject=subject,
                    method=_method,
                    status="dead_letter",
                    rid=rid,
                )
                return
            # Idempotency guard (F-08): a reclaimed/redelivered call may already
            # have executed. Decide whether to (re-)run before touching the upstream.
            if w._idempotency_guard and request_id:
                decision = await w._guard_duplicate(hostname, request_id, pod, message)
                if decision is not None:
                    if decision == "nonidempotent_guard":
                        # Refusing a possibly-applied non-idempotent op — tell the
                        # client definitively instead of letting it hang to timeout.
                        msg_id_val = message.get("id") if isinstance(message, dict) else None
                        if session_id and msg_id_val is not None:
                            await w._session_router.publish_result(
                                session_id,
                                rpc_error(
                                    RPC_DUPLICATE,
                                    msg_id_val,
                                    rid=rid,
                                    request_id=request_id,
                                    message=(
                                        f"Duplicate delivery of a non-idempotent call to {hostname}; "
                                        "not re-executed to avoid a double side effect"
                                    ),
                                ),
                            )
                        await w._r.set(f"result:{request_id}", "1", ex=w._result_marker_ttl)
                    metrics.duplicate_calls_suppressed_total.labels(hostname=hostname, reason=decision).inc()
                    audit_log(
                        "tool dispatch",
                        hostname=hostname,
                        subject=subject,
                        method=_method,
                        status=f"duplicate_{decision}",
                        rid=rid,
                    )
                    return
            _t = time.perf_counter()
            # Execution span parented from the gateway's dispatch span (F-14): the
            # traceparent rode along on the stream entry, so this joins the same
            # end-to-end trace. No-op when tracing is off.
            with tracing.start_span_from_carrier(
                "mcp.tool_call",
                {"traceparent": fields.get("traceparent", "")},
                attributes={"mcp.hostname": hostname, "mcp.method": _method, "mcp.rid": rid},
            ) as _span:
                result = await pod.call_tool(message)
                _dur = time.perf_counter() - _t
                # Distributed-mode tool calls execute here on the worker; record where
                # the work actually happens (the gateway only enqueues).
                if result is None:
                    _status = "noresult"  # notification — no JSON-RPC response expected
                elif isinstance(result, dict) and "error" in result:
                    _status = "error"
                else:
                    _status = "ok"
                if _span is not None:
                    _span.set_attribute("mcp.status", _status)
            metrics.tool_calls_total.labels(hostname=hostname, method=_method, status=_status).inc()
            metrics.tool_call_duration_seconds.labels(hostname=hostname).observe(_dur)
            if result is not None:
                await w._session_router.publish_result(session_id, result)
            # Mark the call as handled so the gateway's timeout watcher (F6)
            # stands down even when the result reached a different gateway replica.
            if request_id:
                await w._r.set(f"result:{request_id}", "1", ex=w._result_marker_ttl)
            # Distributed-mode audit log with execution latency (SRE O2/O3): the
            # gateway only logs "dispatched", so per-call latency lives here.
            audit_log(
                "tool dispatch",
                hostname=hostname,
                subject=subject,
                method=_method,
                status=_status,
                duration_ms=round(_dur * 1000, 1),
                rid=rid,
            )
        except Exception as exc:
            logger.exception(f"Tool call dispatch error for {hostname} session {session_id} rid={rid}")
            # The call was delivered but raised (e.g. an upstream failure that survived
            # the retry policy). Don't let the ack below drop it silently: dead-letter it
            # for inspect/replay, and return a definitive error to the client instead of
            # letting it hang to the F6 timeout (#10). Replay stays safe for a partially-
            # applied non-idempotent op — the F-08 guard refuses a duplicate on re-run.
            try:
                await w._dead_letter(hostname, fields, f"dispatch error: {exc}")
                metrics.tool_calls_total.labels(hostname=hostname, method=_method, status="dead_letter").inc()
                msg_id_val = message.get("id") if isinstance(message, dict) else None
                if session_id and msg_id_val is not None:
                    await w._session_router.publish_result(
                        session_id,
                        rpc_error(
                            RPC_INTERNAL_ERROR,
                            msg_id_val,
                            rid=rid,
                            request_id=request_id,
                            message=f"Tool call to {hostname} failed and was dead-lettered",
                        ),
                    )
                if request_id:
                    await w._r.set(f"result:{request_id}", "1", ex=w._result_marker_ttl)
                audit_log(
                    "tool dispatch",
                    hostname=hostname,
                    subject=subject,
                    method=_method,
                    status="dead_letter",
                    rid=rid,
                )
            except Exception:
                logger.exception(f"Failed to dead-letter failed call {msg_id} for {hostname}")
        finally:
            await w._r.xack(stream, group, msg_id)
