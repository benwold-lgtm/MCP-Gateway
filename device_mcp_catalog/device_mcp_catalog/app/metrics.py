# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""Prometheus exposition for the catalog service (ADR-0020 §7b).

**This service had no metrics plane, deliberately, and now has one for a single condition.**
§7b argues that a console holding another tenant's catalog credential is a should-never-happen
condition and belongs on the alert plane rather than in a log nobody reads — reusing the pattern
ADR-0023 established for break-glass activation rather than inventing a third notification
mechanism. Making this service a scrape target is the price of that, and it is real new surface
in a component whose separate failure domain is deliberate (§7).

So the scope here is narrow on purpose: the counters below exist to be alerted on. This is not a
general observability plane for the catalog, and request-rate/latency instrumentation is
deliberately absent — the gateway's `metrics.py` is where that pattern lives, and copying it
here would be building an observability story nobody asked for on the back of one alert.

Served on a **dedicated port** (default 9100), never on the API port. The API is entirely
credential-gated; an unauthenticated `/metrics` route beside it would be a hole in exactly the
surface §7a just finished closing. Same arrangement, and the same F-36 caveat, as the gateway:
unauthenticated by default and restricted by NetworkPolicy, with an optional bearer token.
"""

from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer
from typing import Optional

from loguru import logger
from prometheus_client import Counter, Gauge
from prometheus_client import start_http_server as _start_http_server

#: Always 1 while this process is exposing metrics — and the only series here that exists in
#: normal operation.
#:
#: The two counters below are label-bearing, so a `Counter` that has never been incremented is
#: not a series at all: in a healthy estate there is nothing to query. That makes
#: `MCPCatalogCredentialMisdelivery` unable to tell "no misdeliveries" from "Prometheus has
#: never reached this pod" — a NetworkPolicy that drops the scrape, an un-applied
#: ServiceMonitor, a wrong namespace label — and silence is the failure mode a
#: should-never-happen alert cannot afford, because it looks exactly like success.
#:
#: So the alert plane watches for THIS being absent, which is the idiom the gateway's own
#: `MCPNoLiveWorkers` (`absent(mcp_worker_pods)`) already uses. It covers every cause of a
#: broken scrape path rather than the one an operator was warned about in a comment.
catalog_info = Gauge(
    "catalog_info",
    "Always 1 while the catalog is exposing metrics. Exists so the alert plane can detect that "
    "it has stopped being scraped at all (ADR-0020 §7b) — the counters below are absent in "
    "normal operation and cannot carry that signal.",
)

#: A tenant console presented a credential that is not its own — §7b's condition. Labelled by
#: the tenant the CALLER declared itself to be (which is the deployment that is broken) and by
#: what the credential actually turned out to be. Cardinality is bounded by the tenant count.
credential_misdelivery_total = Counter(
    "catalog_credential_misdelivery_total",
    "Requests refused because the caller's declared tenant disagreed with its credential "
    "(ADR-0020 §7b). A provisioning-time misdelivery: the credential is valid, and it is in "
    "the wrong console. Never expected to be non-zero.",
    ["declared_tenant", "credential_kind"],
)

#: A tenant caller that sent no declaration at all. Not misdelivery — a client that has not been
#: updated, or a direct caller that never declared. Separate metric rather than a label on the
#: one above, because conflating "the wrong credential is deployed somewhere" with "a client is
#: out of date" would make the page-severity alert fire for the second one.
tenant_declaration_missing_total = Counter(
    "catalog_tenant_declaration_missing_total",
    "Requests refused because a tenant caller declared no tenant (ADR-0020 §7b). That "
    "console's catalog features are refused until it does.",
    ["credential_tenant"],
)


def start_metrics_server(port: int, auth_token: Optional[str] = None) -> bool:
    """Start the exposition server. Tolerant of a port already in use, like the gateway's.

    Non-fatal on failure for the same reason the database is: this service must come up and
    report its own state rather than refuse to start over a subsidiary concern. A caller table
    that cannot be resolved is the one thing that IS fatal here (see `config.py`), and the
    distinction is deliberate — that one decides who a request is; this one decides who hears
    about it afterwards.
    """
    catalog_info.set(1)
    try:
        if auth_token:
            httpd = ThreadingHTTPServer(("", port), _authenticated_handler(auth_token))
            threading.Thread(target=httpd.serve_forever, daemon=True, name="catalog-metrics").start()
            logger.info(f"catalog metrics server listening on :{port} (bearer-token authenticated)")
        else:
            _start_http_server(port)
            logger.info(f"catalog metrics server listening on :{port} (unauthenticated — restrict via NetworkPolicy)")
        return True
    except OSError as exc:
        logger.warning(f"catalog metrics server not started on :{port}: {exc}")
        return False


def _authenticated_handler(token: str):
    """Bearer-gated exposition handler, mirroring the gateway's F-36 option."""
    import secrets

    from prometheus_client import MetricsHandler

    class _AuthMetricsHandler(MetricsHandler):
        def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's own naming
            header = self.headers.get("Authorization", "")
            scheme, _, presented = header.partition(" ")
            if scheme.lower() != "bearer" or not presented or not secrets.compare_digest(presented, token):
                self.send_response(401)
                self.end_headers()
                return
            super().do_GET()

        def log_message(self, *args: object) -> None:  # silence per-scrape stderr noise
            pass

    return _AuthMetricsHandler
