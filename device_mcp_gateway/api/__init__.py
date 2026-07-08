# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0. See LICENSE in the project root for details.
"""HTTP route modules, one per concern, assembled by ``main.create_app``.

Every module exposes a bare ``router`` (no auth of its own); ``create_app`` mounts
them under a single parent router carrying the ``authenticate_request`` dependency
(probes excepted — they are unauthenticated and unversioned by design). Handlers
read all runtime state from ``request.app.state`` so the modules stay free of
app-factory closure state.
"""
