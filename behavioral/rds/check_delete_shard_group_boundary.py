"""delete-shard-group-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-shard-group-boundary"
GROUP = 'shard_groups'
SERVICES = ['rds']

ERR_SHARD_GROUP_NOT_FOUND = "DBShardGroupNotFound"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBShardGroup on an unknown DBShardGroupIdentifier fails DBShardGroupNotFound.

    An unfiltered DescribeDBShardGroups first proves the API is reachable, and an independent Describe
    of the same identifier confirms the absence.
    """
    rds = ctx.client("rds")

    rds.describe_db_shard_groups()

    bogus_shard = ctx.unique_name("sim2real-behav-shardgrp-missing-")
    delete_code, delete_message = _error_code(
        lambda: rds.delete_db_shard_group(DBShardGroupIdentifier=bogus_shard)
    )
    assert delete_code == ERR_SHARD_GROUP_NOT_FOUND, f"unexpected error code: {delete_code}"
    assert delete_message == "DB shard group not found or can not be accessed", delete_message

    describe_code, describe_message = _error_code(
        lambda: rds.describe_db_shard_groups(DBShardGroupIdentifier=bogus_shard)
    )
    assert describe_code == ERR_SHARD_GROUP_NOT_FOUND, (
        f"an independent read of the same identifier returned {describe_code!r}, "
        f"expected {ERR_SHARD_GROUP_NOT_FOUND!r}"
    )
    assert describe_message == f"DBShardGroup {bogus_shard} not found.", describe_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
