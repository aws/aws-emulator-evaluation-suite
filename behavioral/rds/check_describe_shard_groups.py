"""describe-shard-groups."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-shard-groups"
GROUP = 'shard_groups'
SERVICES = ['rds']


def _client_error(fn) -> dict:
    """Call fn() and return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDBShardGroups succeeds unfiltered, an unknown DBShardGroupIdentifier is rejected with
    DBShardGroupNotFound, and a MaxRecords below 20 is rejected by the service."""
    rds = ctx.client("rds")
    resp = rds.describe_db_shard_groups()
    groups = resp.get("DBShardGroups")
    assert isinstance(groups, list), f"expected DBShardGroups to be a list, got {groups!r}"

    bogus_id = ctx.unique_name("sim2real-behav-shardgrp-missing-")
    err = _client_error(lambda: rds.describe_db_shard_groups(DBShardGroupIdentifier=bogus_id))
    assert err.get("Code") == "DBShardGroupNotFound", f"unexpected error code: {err.get('Code')}"
    expected = f"DBShardGroup {bogus_id} not found."
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # MaxRecords carries the same 20-100 range constraint in botocore's own model, so a
    # validated client never lets an out-of-range value leave the process. Disable
    # client-side validation so the request actually reaches RDS and it is the service's
    # own rejection that gets asserted, not botocore's local ParamValidationError.
    unvalidated_rds = ctx.client("rds", config=Config(parameter_validation=False))
    err2 = _client_error(lambda: unvalidated_rds.describe_db_shard_groups(MaxRecords=5))
    assert err2.get("Code") == "InvalidParameterValue", f"unexpected error code: {err2.get('Code')}"
    expected2 = (
        "1 validation error detected: Value '5' at 'maxRecords' failed to satisfy constraint: "
        "Member must have value greater than or equal to 20"
    )
    assert err2.get("Message") == expected2, (
        f"expected message {expected2!r}, got {err2.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
