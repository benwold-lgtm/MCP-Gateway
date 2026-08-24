# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Break-glass use is loud, and reactivation frequency is flagged (ADR-0023 §2/§3).

Slice 1 made a break-glass credential name a person; slice 2 gave it a lifetime. This is
what finally *consumes* ``Principal.break_glass``: until now the fact was carried and
nothing read it.

Two distinct events, because they answer two different questions:

- **Every use** emits ``auth.break_glass`` at WARNING with ``severity="high"`` — a dedicated
  record, not ordinary static-key authentication folded into request logging where it reads
  as unremarkable (§2). This is the attribution trail: who, what, when, which request.
- **Every activation** emits ``auth.break_glass.activated`` at ERROR with
  ``severity="critical"`` — the notification trigger. An *activation* is a use that follows
  a quiet gap, so one incident worked through over hours is one activation however many
  calls it takes.

**Why the split, and why the notification hangs off the activation rather than the use.**
§3 is explicit that there is no throttling within an active session — a real incident may
need many calls over hours and cutting that off is the one failure this mechanism cannot
afford. The same reasoning applies to the notification: firing one per request would make
the loud signal unreadable during exactly the incident it exists to announce, and ADR-0023's
own carve-out paragraph names per-request notification as the thing to avoid. Per-use stays
in the audit chain, where volume costs nothing and completeness is the point.

**Nothing here ever blocks.** The reactivation-frequency check raises a review flag and
increments a counter; it has no path that refuses a request. A credential that locked
someone out during a second genuine emergency would be worse than the behaviour it prevents.

**Nothing here can fail a request either.** Recording activity is best-effort by
construction: the tracker is wrapped, and a Redis outage degrades to the in-process tracker
rather than to a 500. Break-glass is the path that has to work when everything else is
broken, so the observability *of* that path must never be able to break it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional, Protocol

from loguru import logger

from device_mcp_gateway import metrics
from device_mcp_gateway.audit import AUDIT_OUTCOME_SUCCESS, audit_event
from device_mcp_gateway.shared.keys import KEYS

#: Starting defaults from ADR-0023 §3 — instrumented from day one so the real values come
#: from observed usage rather than from a guess frozen into code. All three are overridable
#: under ``gateway.``.
DEFAULT_SESSION_GAP_MINUTES = 60
DEFAULT_REVIEW_WINDOW_DAYS = 30
DEFAULT_REVIEW_THRESHOLD = 3


@dataclass(frozen=True)
class Activity:
    """What one recorded use turned out to be.

    ``activations`` and ``seconds_since_last_use`` are only meaningful on an activation —
    they are read as part of the same round trip that detects one, and a mid-session use
    deliberately costs a single write with no reads at all.
    """

    activation: bool
    activations: int = 0
    seconds_since_last_use: Optional[float] = None
    #: True when the tracker could not reach shared state and answered from process-local
    #: memory instead. The activation signal is then per-replica and best-effort.
    degraded: bool = False


class BreakGlassActivity(Protocol):
    async def record(self, subject: str, *, gap_seconds: int, window_seconds: int) -> Activity:
        """Record one use of ``subject``'s credential and classify it."""
        ...


class InMemoryBreakGlassActivity:
    """Per-process tracker for embedded mode, tests, and the degraded fallback.

    Correct for a single-replica deployment and honest about being nothing more in a
    multi-replica one: each replica then sees only the uses routed to it, so an activation
    can be reported once per replica. That is over-reporting a loud event, which is the
    right direction for this signal to be wrong in.
    """

    def __init__(self) -> None:
        # subject -> (last_use_epoch, activations, window_expires_epoch)
        self._seen: dict[str, tuple[float, int, float]] = {}

    async def record(self, subject: str, *, gap_seconds: int, window_seconds: int) -> Activity:
        now = time.time()
        last_use, activations, window_expires = self._seen.get(subject, (0.0, 0, 0.0))
        if now >= window_expires:
            # A full quiet window has passed: the count starts clean, same semantics as the
            # Redis key having expired.
            activations = 0
        if last_use and now - last_use < gap_seconds:
            self._seen[subject] = (now, activations, window_expires)
            return Activity(activation=False)
        activations += 1
        self._seen[subject] = (now, activations, now + window_seconds)
        return Activity(
            activation=True,
            activations=activations,
            seconds_since_last_use=(now - last_use) if last_use else None,
        )


class RedisBreakGlassActivity:
    """Tracker shared across gateway replicas, so an activation is counted once.

    Falls back to an in-process tracker on any Redis error rather than losing the signal.
    Break-glass gets reached for during infrastructure failures, so "Redis is unavailable"
    is not an edge case here — it is a substantial fraction of the times this code runs.
    """

    def __init__(self, redis_client) -> None:
        self._r = redis_client
        self._fallback = InMemoryBreakGlassActivity()

    async def record(self, subject: str, *, gap_seconds: int, window_seconds: int) -> Activity:
        try:
            return await self._record(subject, gap_seconds=gap_seconds, window_seconds=window_seconds)
        except Exception as exc:  # noqa: BLE001 — see the class docstring
            logger.warning(
                f"Break-glass activity tracking fell back to process-local state for {subject!r}: "
                f"{exc}. The audit record is unaffected; the reactivation-frequency signal is "
                "per-replica until Redis returns."
            )
            activity = await self._fallback.record(subject, gap_seconds=gap_seconds, window_seconds=window_seconds)
            return Activity(
                activation=activity.activation,
                activations=activity.activations,
                seconds_since_last_use=activity.seconds_since_last_use,
                degraded=True,
            )

    async def _record(self, subject: str, *, gap_seconds: int, window_seconds: int) -> Activity:
        now = time.time()
        if gap_seconds > 0:
            session_key = KEYS.break_glass_session(subject)
            # SET ... EX ... GET: write the session marker and learn in the same round trip
            # whether one was already there. A returned value means we are inside an active
            # session; None means the marker had expired, which IS the activation signal.
            previous = await self._r.set(session_key, str(now), ex=gap_seconds, get=True)
            if previous is not None:
                return Activity(activation=False)
        # A gap of zero means "treat every use as an activation", which is a legitimate
        # setting and NOT expressible as a TTL: Redis rejects `EX 0` outright. Left
        # unhandled it raised on every single request, and the except-and-fall-back above
        # turned that into silent per-replica tracking plus a warning per call — during an
        # incident, which is the only time any of this code runs. Skipping the marker is
        # what a zero-length session actually means.

        window_key = KEYS.break_glass_window(subject)
        pipe = self._r.pipeline(transaction=True)
        # HGET runs before HSET inside the MULTI/EXEC, so it yields the *previous* last_use.
        pipe.hget(window_key, "last_use")
        pipe.hincrby(window_key, "activations", 1)
        pipe.hset(window_key, "last_use", str(now))
        # Plain EXPIRE, not EXPIRE NX: the window slides from the last activation. See
        # KeyBuilder.break_glass_window for why that is the shape we want here.
        pipe.expire(window_key, window_seconds)
        last_use_raw, activations, _, _ = await pipe.execute()
        return Activity(
            activation=True,
            activations=int(activations),
            seconds_since_last_use=_seconds_since(last_use_raw, now),
        )


def _seconds_since(raw: Any, now: float) -> Optional[float]:
    """Decode a stored epoch and return the elapsed seconds, or None if unusable.

    Defensive about bytes because fakeredis does not honour ``decode_responses`` for hash
    fields the way real Redis does — the same trap already documented in
    ``shared/session_router.py``.
    """
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        elapsed = now - float(raw)
    except (TypeError, ValueError):
        return None
    return elapsed if elapsed >= 0 else None


def _tracker(app_state: Any) -> BreakGlassActivity:
    """The app's tracker, creating a process-local one if nothing was wired.

    An app built without the wiring (a test, an embedded host) still gets the events. The
    alternative — skipping the signal when the tracker is missing — would make the loud
    path silently quiet in exactly the setups least likely to notice.
    """
    tracker = getattr(app_state, "break_glass_activity", None)
    if tracker is None:
        tracker = InMemoryBreakGlassActivity()
        try:
            app_state.break_glass_activity = tracker
        except Exception:  # noqa: BLE001 — a read-only fake state object is not a failure
            pass
    return tracker


def _settings(app_state: Any) -> tuple[int, int, int]:
    """(gap_seconds, window_seconds, review_threshold) from config, with §3's defaults."""
    config = getattr(app_state, "config", None) or {}
    gateway = config.get("gateway", {}) if isinstance(config, dict) else {}
    gap = max(0, int(gateway.get("break_glass_session_gap_minutes", DEFAULT_SESSION_GAP_MINUTES))) * 60
    # A window floor of one second, because `EXPIRE key 0` DELETES the key rather than
    # expiring it later — a review window of zero would silently discard the counter it was
    # meant to bound instead of doing nothing.
    window = max(1, int(gateway.get("break_glass_review_window_days", DEFAULT_REVIEW_WINDOW_DAYS)) * 86400)
    threshold = int(gateway.get("break_glass_review_threshold", DEFAULT_REVIEW_THRESHOLD))
    return gap, window, threshold


async def note_break_glass_use(app_state: Any, principal: Any, *, rid: str = "-", target: str = "-") -> None:
    """Emit the loud events for one authenticated break-glass request.

    Called from ``authenticate_request`` once the Principal is resolved, and only when
    ``principal.break_glass`` is set — a fact the credential itself carries, so there is one
    place that decides it rather than three call sites recomputing it.

    Every failure mode here is swallowed. This function observes the emergency access path;
    it must never be the reason that path fails.
    """
    subject = getattr(principal, "subject", "unknown")
    try:
        metrics.break_glass_uses_total.labels(subject=subject).inc()
        audit_event(
            "auth.break_glass",
            subject=subject,
            outcome=AUDIT_OUTCOME_SUCCESS,
            rid=rid,
            target=target,
            level="WARNING",
            severity="high",
            auth_method=getattr(principal, "auth_method", "break_glass"),
            # False for the unnamed env-var keys slice 4 flags in an OIDC deployment. The
            # record has to carry this: "break-glass was used" and "break-glass was used by
            # Alice" are different facts, and a reader who cannot tell them apart will assume
            # the stronger one.
            attributable=getattr(principal, "attributable", True),
        )

        gap, window, threshold = _settings(app_state)
        activity = await _tracker(app_state).record(subject, gap_seconds=gap, window_seconds=window)
        if not activity.activation:
            return

        flagged = activity.activations > threshold
        metrics.break_glass_activations_total.labels(subject=subject).inc()
        if flagged:
            metrics.break_glass_review_flags_total.labels(subject=subject).inc()

        window_days = window // 86400
        audit_event(
            "auth.break_glass.activated",
            subject=subject,
            outcome=AUDIT_OUTCOME_SUCCESS,
            rid=rid,
            target=target,
            level="ERROR",
            severity="critical",
            activations_in_window=activity.activations,
            review_window_days=window_days,
            review_flag=flagged,
            days_since_last_use=_days(activity.seconds_since_last_use),
            signal_degraded=activity.degraded,
            attributable=getattr(principal, "attributable", True),
        )
        _log_activation(
            subject,
            activity,
            threshold=threshold,
            window_days=window_days,
            flagged=flagged,
            attributable=getattr(principal, "attributable", True),
        )
    except Exception as exc:  # noqa: BLE001 — see the docstring
        logger.warning(f"Break-glass event emission failed for {subject!r}: {exc}. Access itself is unaffected.")


def _days(seconds: Optional[float]) -> Optional[float]:
    return None if seconds is None else round(seconds / 86400, 2)


def _log_activation(
    subject: str,
    activity: Activity,
    *,
    threshold: int,
    window_days: int,
    flagged: bool,
    attributable: bool = True,
) -> None:
    since = _days(activity.seconds_since_last_use)
    history = "first recorded activation" if since is None else f"last activated {since} day(s) ago"
    # An unnamed env-var key (ADR-0023 slice 4) names no person. Saying so in the line an
    # operator actually reads matters more than the audit field: "break-glass was used" and
    # "break-glass was used by Alice" are different facts, and a subject like `key:legacy`
    # looks enough like an identity to be mistaken for one.
    unnamed = (
        ""
        if attributable
        else (
            " ⚠️ This credential has no configured name, so this record CANNOT say who used "
            "it — only that someone did. Provision a named break_glass gateway.rbac entry "
            "per person to get attribution."
        )
    )
    if flagged:
        logger.error(
            f"BREAK-GLASS REACTIVATION FLAG: {subject} has activated "
            f"{activity.activations} time(s) in the last {window_days} day(s), over the "
            f"threshold of {threshold} ({history}). Nothing has been blocked and nothing will "
            "be — this is a review flag, not a limit. Repeated activation across separate "
            "weeks means the emergency path has become routine access: find out what normal "
            "work is reaching for it and give that work its own credential (ADR-0023 §3)." + unnamed
        )
        return
    logger.warning(
        f"BREAK-GLASS ACTIVATED: {subject} ({history}); "
        f"{activity.activations} activation(s) in the last {window_days} day(s). If this was "
        "not an authorized emergency, treat the credential as compromised and reissue it." + unnamed
    )
