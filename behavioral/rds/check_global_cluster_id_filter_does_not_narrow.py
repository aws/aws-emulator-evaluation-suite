"""global-cluster-id-filter-does-not-narrow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-cluster-id-filter-does-not-narrow"
GROUP = "global_clusters"
SERVICES = ["rds"]


def _teardown(undo, *not_found: str):
    """Cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _is_not_found(fn) -> bool:
    """True once fn() raises GlobalClusterNotFoundFault; False while it still succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "GlobalClusterNotFoundFault"
    return False


def _filtered_ids(rds, filter_value: str) -> set[str]:
    """Global cluster identifiers DescribeGlobalClusters returns under a global-cluster-id filter."""
    ids: set[str] = set()
    paginator = rds.get_paginator("describe_global_clusters")
    for page in paginator.paginate(Filters=[{"Name": "global-cluster-id", "Values": [filter_value]}]):
        ids.update(c["GlobalClusterIdentifier"] for c in page["GlobalClusters"])
    return ids


def _poll_filtered_ids(rds, filter_value: str, target_id: str, *, present: bool,
                        budget_s: float = 180.0, interval_s: float = 5.0) -> set[str]:
    """Poll the global-cluster-id filter until target_id's membership matches `present`."""
    deadline = time.monotonic() + budget_s
    ids = _filtered_ids(rds, filter_value)
    while (target_id in ids) != present and time.monotonic() < deadline:
        time.sleep(interval_s)
        ids = _filtered_ids(rds, filter_value)
    return ids


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeGlobalClusters' global-cluster-id filter never narrows its result: an owned global
    cluster appears whether the filter names its own id or an id never created, while the
    GlobalClusterIdentifier parameter matches exactly and faults for an id never created."""
    rds = ctx.client("rds")
    own_id = ctx.unique_name("sim2real-behav-gc-filt-")
    absent_id = own_id + "-absent"

    rds.create_global_cluster(GlobalClusterIdentifier=own_id, Engine="aurora-mysql")
    ctx.on_cleanup(
        _teardown(lambda: rds.delete_global_cluster(GlobalClusterIdentifier=own_id), "GlobalClusterNotFoundFault")
    )

    control = rds.describe_global_clusters(GlobalClusterIdentifier=own_id)["GlobalClusters"]
    assert control and control[0]["GlobalClusterIdentifier"] == own_id, (
        f"expected {own_id!r} to describe as a positive control, got {control!r}"
    )

    _ABSENT_PARAM = ("GlobalClusterNotFoundFault", f"Global cluster '{absent_id}' not found")
    expect_error(lambda: rds.describe_global_clusters(GlobalClusterIdentifier=absent_id), *_ABSENT_PARAM)

    by_own = _poll_filtered_ids(rds, own_id, own_id, present=True)
    assert own_id in by_own, f"filtering by its own id {own_id!r} did not include it: {by_own!r}"
    by_absent = _poll_filtered_ids(rds, absent_id, own_id, present=True)
    assert own_id in by_absent, (
        f"filtering by {absent_id!r}, never created, excluded {own_id!r} which it still held: {by_absent!r}"
    )

    rds.delete_global_cluster(GlobalClusterIdentifier=own_id)

    deadline = time.monotonic() + 300
    param_gone = False
    while time.monotonic() < deadline:
        param_gone = _is_not_found(lambda: rds.describe_global_clusters(GlobalClusterIdentifier=own_id))
        if param_gone:
            break
        time.sleep(5)
    assert param_gone, f"deleted {own_id!r} still described as present after 300s"

    _DELETED_PARAM = ("GlobalClusterNotFoundFault", f"Global cluster '{own_id}' not found")
    expect_error(lambda: rds.describe_global_clusters(GlobalClusterIdentifier=own_id), *_DELETED_PARAM)

    gone_own = _poll_filtered_ids(rds, own_id, own_id, present=False)
    assert own_id not in gone_own, f"{own_id!r} still appears under its own id filter after delete: {gone_own!r}"
    gone_absent = _poll_filtered_ids(rds, absent_id, own_id, present=False)
    assert own_id not in gone_absent, (
        f"{own_id!r} still appears under the never-created id filter after delete: {gone_absent!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
