"""Single-source runtime metadata exposed by health endpoints."""

from __future__ import annotations

import os
import re
from importlib.metadata import PackageNotFoundError, version


SERVICE_ID = "kodi-profile-sync-server"
API_VERSION = "v1"
DATABASE_SCHEMA_VERSION = 5
SAFE_BUILD = re.compile(r"^[A-Za-z0-9._:@+-]{1,128}$")


def package_version():
    try:
        return version("kodi-profile-sync-server")
    except PackageNotFoundError:
        return "0.0.0+source"


def build_identifier():
    value = os.environ.get("PROFILE_SYNC_BUILD", "development")
    return value if SAFE_BUILD.fullmatch(value) else "invalid"


def runtime_metadata():
    return {
        "service": SERVICE_ID,
        "api_version": API_VERSION,
        "version": package_version(),
        "build": build_identifier(),
        "database_schema": DATABASE_SCHEMA_VERSION,
    }
