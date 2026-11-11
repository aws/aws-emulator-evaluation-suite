"""tag-key-reserved-aws-prefix-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-key-reserved-aws-prefix-rejected"
GROUP = "representation"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"
_RESERVED_KEY = "aws:sim2real-reserved"
_OK_KEY = "sim2real-ok-tag"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """AddTagsToResource rejects a tag key prefixed with the reserved 'aws:' namespace
    (documented in the RDS Tag object as forbidden); the reserved-prefix tag is never
    stored, while a same-call-shape tag with an ordinary key still succeeds."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-tagreserved-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))
    inst = _wait_for_instance_status(rds, db_id, "available", timeout_s=900)
    arn = inst["DBInstanceArn"]

    # Break exactly one thing: a tag key in the reserved "aws:" namespace.
    error = _client_error(
        lambda: rds.add_tags_to_resource(
            ResourceName=arn, Tags=[{"Key": _RESERVED_KEY, "Value": "whatever"}]
        )
    )
    assert error["Code"] == "InvalidParameterValue", f"unexpected error: {error!r}"
    assert error["Message"] == 'Tag keys cannot start with the reserved prefix "aws:".', (
        f"unexpected message {error['Message']!r}"
    )

    # Effect absent: the reserved-prefix tag never landed.
    tag_list = rds.list_tags_for_resource(ResourceName=arn)["TagList"]
    assert not any(t["Key"] == _RESERVED_KEY for t in tag_list), (
        f"reserved-prefix tag key was stored despite rejection: {tag_list!r}"
    )

    # Positive control: an ordinary tag key in the same shape of call still succeeds.
    rds.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": _OK_KEY, "Value": "yes"}])
    tag_list_after = rds.list_tags_for_resource(ResourceName=arn)["TagList"]
    assert any(t["Key"] == _OK_KEY and t["Value"] == "yes" for t in tag_list_after), (
        f"ordinary tag was not accepted: {tag_list_after!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A success raises: AWS refuses this call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"AWS refuses this call, but it succeeded and returned {result!r}")


def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        if inst["DBInstanceStatus"] == status:
            return inst
        time.sleep(2)
    raise AssertionError(f"DB instance {db_id} never reached status={status!r} in {timeout_s}s")


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFoundFault":
            raise


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
