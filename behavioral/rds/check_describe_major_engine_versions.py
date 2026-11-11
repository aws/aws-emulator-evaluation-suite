"""describe-major-engine-versions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-major-engine-versions"
GROUP = 'engine_versions'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBMajorEngineVersions: the 'mysql' engine has a non-empty, real set of describable
    major versions. Overly-permissive boundary: MaxRecords is documented as constrained to the
    20-100 range; an above-range value must be rejected rather than silently clamped.
    """
    rds = ctx.client("rds")
    resp = rds.describe_db_major_engine_versions(Engine="mysql")
    majors = resp.get("DBMajorEngineVersions", [])
    assert majors, "expected at least one mysql major engine version"
    assert all(m["Engine"] == "mysql" for m in majors)
    assert all("MajorEngineVersion" in m for m in majors)

    err = _rejection(
        lambda: rds.describe_db_major_engine_versions(Engine="mysql", MaxRecords=1000)
    )
    assert err.get("Code") == "InvalidParameterValue", f"unexpected error: {err}"
    assert err.get("Message") == (
        "1 validation error detected: Value '1000' at 'maxRecords' failed to satisfy "
        "constraint: Member must have value less than or equal to 100"
    ), f"unexpected InvalidParameterValue message: {err}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
