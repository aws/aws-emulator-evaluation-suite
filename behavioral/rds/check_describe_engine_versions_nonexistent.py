"""describe-engine-versions-nonexistent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-engine-versions-nonexistent"
GROUP = 'engine_versions'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDBEngineVersions for a nonexistent engine raises InvalidParameterValue,
    while the identical call for a real engine still succeeds (positive control)."""
    rds = ctx.client("rds")

    control = rds.describe_db_engine_versions(Engine="mysql", MaxRecords=20)
    assert control["DBEngineVersions"], "positive control: mysql returned no engine versions"

    err = _rejection(
        lambda: rds.describe_db_engine_versions(Engine="sim2real-fake-engine", MaxRecords=20)
    )
    assert err.get("Code") == "InvalidParameterValue", (
        f"Expected InvalidParameterValue for fake engine, got {err}"
    )
    assert err.get("Message") == "Unrecognized engine name: sim2real-fake-engine", (
        f"unexpected InvalidParameterValue message: {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
