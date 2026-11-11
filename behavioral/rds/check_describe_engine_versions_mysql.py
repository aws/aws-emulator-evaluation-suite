"""describe-engine-versions-mysql."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-engine-versions-mysql"
GROUP = 'engine_versions'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBEngineVersions for mysql returns only mysql versions and one DefaultOnly version.

    The default is a minor of its own major line and family; an out-of-range MaxRecords is rejected.
    """
    rds = ctx.client("rds")
    resp = rds.describe_db_engine_versions(Engine="mysql", MaxRecords=20)
    versions = resp["DBEngineVersions"]
    assert len(versions) > 0, "No MySQL engine versions returned"
    assert all(v["Engine"] == "mysql" for v in versions), (
        f"non-mysql entry in mysql-filtered response: {versions}"
    )
    assert all("EngineVersion" in v for v in versions), (
        "an entry is missing EngineVersion"
    )
    assert all("DBParameterGroupFamily" in v for v in versions), (
        "an entry is missing DBParameterGroupFamily"
    )

    default = rds.describe_db_engine_versions(Engine="mysql", DefaultOnly=True)["DBEngineVersions"]
    assert len(default) == 1, f"DefaultOnly must return exactly one mysql version, got {default!r}"
    entry = default[0]
    assert entry["Engine"] == "mysql", f"DefaultOnly returned a non-mysql entry: {entry!r}"
    major = entry["MajorEngineVersion"]
    assert re.fullmatch(r"[0-9]+\.[0-9]+", major), f"unexpected MajorEngineVersion {major!r}"
    assert re.fullmatch(re.escape(major) + r"\.[0-9]+", entry["EngineVersion"]), (
        f"default EngineVersion {entry['EngineVersion']!r} is not a minor of major {major!r}"
    )
    assert entry["DBParameterGroupFamily"] == f"mysql{major}", (
        f"default version family {entry['DBParameterGroupFamily']!r} does not match major {major!r}"
    )
    assert entry["Status"] == "available", f"default version status {entry['Status']!r}"

    err = _rejection(
        lambda: rds.describe_db_engine_versions(Engine="mysql", MaxRecords=1000)
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"expected MaxRecords above 100 to be rejected, got {err}"
    )
    assert err.get("Message") == "Invalid value 1000 for MaxRecords. Must be between 20 and 100", (
        f"unexpected InvalidParameterValue message: {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
