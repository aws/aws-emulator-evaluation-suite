"""snapshot-not-found-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(), which must raise a ClientError; return its (Error.Code, Error.Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError but the call SUCCEEDED")

def _assert_error(fn, expected):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized); return the message."""
    code, actual = _error(fn)
    assert _fault_base(code) == _fault_base(expected), f"expected {expected}, got {code} ({actual!r})"
    return actual

CHECK = "snapshot-not-found-semantics"
GROUP = 'snapshot'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSnapshots on an unknown name returns an EMPTY LIST while mutations raise SnapshotNotFound."""
    ec = ctx.client("elasticache")
    bogus = ctx.unique_name("sim2real-behav-ecs-missing-")
    # Asymmetry that matters: the read is a filter (empty result), not a 404.
    resp = ec.describe_snapshots(SnapshotName=bogus)
    assert resp["Snapshots"] == [], resp

    message = _assert_error(
        lambda: ec.delete_snapshot(SnapshotName=bogus),
        "SnapshotNotFoundFault",
    )
    assert message == f"Snapshot with name {bogus} not found", message
    message = _assert_error(
        lambda: ec.copy_snapshot(
            SourceSnapshotName=bogus, TargetSnapshotName=ctx.unique_name("sim2real-behav-ecs-dst-"),
        ),
        "SnapshotNotFoundFault",
    )
    assert message == f"Snapshot with name {bogus} not found", message
    # Snapshotting a cluster that does not exist is a CacheCluster problem.
    missing_cluster = ctx.unique_name("sim2real-behav-ecc-missing-")
    message = _assert_error(lambda: ec.create_snapshot(
        CacheClusterId=missing_cluster,
        SnapshotName=ctx.unique_name("sim2real-behav-ecs-x-"),
    ), "CacheClusterNotFoundFault")
    assert message == f"Cache cluster not found: {missing_cluster}", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
