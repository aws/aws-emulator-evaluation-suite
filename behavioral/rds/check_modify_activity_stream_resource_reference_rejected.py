"""modify-activity-stream-resource-reference-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-activity-stream-resource-reference-rejected"
GROUP = "activity_stream"
SERVICES = ["rds"]


def _rejection(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyActivityStream rejects a resource ARN naming a DB instance that does not exist with
    DBInstanceNotFound, and one shaped as a DB cluster ARN with InvalidParameterValue, while a
    plain describe on the same account still succeeds."""
    rds = ctx.client("rds")

    control = rds.describe_db_instances(MaxRecords=20)
    assert "DBInstances" in control, (
        f"positive control failed: unfiltered describe_db_instances returned {control!r}"
    )

    ghost_instance = ctx.unique_name("sim2real-dbi-")
    instance_arn = f"arn:aws:rds:{ctx.region}:{ctx.account}:db:{ghost_instance}"
    err_instance = _rejection(
        lambda: rds.modify_activity_stream(
            ResourceArn=instance_arn, AuditPolicyState="locked"
        )
    )
    assert err_instance.get("Code") == "DBInstanceNotFound", (
        f"ModifyActivityStream on a nonexistent DB instance ARN: expected DBInstanceNotFound, "
        f"got {err_instance}"
    )
    expected_instance_msg = f"DBInstance not found: {ghost_instance}"
    assert err_instance.get("Message") == expected_instance_msg, err_instance.get("Message")

    ghost_cluster = ctx.unique_name("sim2real-dbc-")
    cluster_arn = f"arn:aws:rds:{ctx.region}:{ctx.account}:cluster:{ghost_cluster}"
    err_cluster = _rejection(
        lambda: rds.modify_activity_stream(
            ResourceArn=cluster_arn, AuditPolicyState="locked"
        )
    )
    assert err_cluster.get("Code") == "InvalidParameterValue", (
        f"ModifyActivityStream on a DB-cluster-shaped ARN: expected InvalidParameterValue, "
        f"got {err_cluster}"
    )
    expected_cluster_msg = "You can't modify the database activity stream on this resource."
    assert err_cluster.get("Message") == expected_cluster_msg, err_cluster.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
