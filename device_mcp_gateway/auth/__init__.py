# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 Ben Wold. All rights reserved.
# Licensed under the Elastic License 2.0. See LICENSE in the project root for details.
"""Auth package - API key and OAuth2/JWT handlers."""

# Re-export for convenience
from .base import AbstractAuth
from .api_key import ApiKeyAuth
from .oauth2 import OAuth2Auth

__all__ = ["AbstractAuth", "ApiKeyAuth", "OAuth2Auth"]
