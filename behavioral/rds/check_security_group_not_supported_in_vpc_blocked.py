"""security-group-not-supported-in-vpc-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-not-supported-in-vpc-blocked"
GROUP = "overly-permissive"
SERVICES = ["rds"]
_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]
_USE_MESSAGE = (
    "DB Security Groups can only be associated with VPC DB Instances using API versions "
    "2012-01-15 through 2012-09-17."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a VPC-only account CreateDBSecurityGroup is either rejected as not supported, or the
    created group is refused by CreateDBInstance for a VPC instance and no instance exists;
    an unrelated CreateDBParameterGroup still succeeds."""
    rds = ctx.client("rds")
    sg_name = ctx.unique_name("sim2real-dbsg-")

    try:
        rds.create_db_security_group(
            DBSecurityGroupName=sg_name,
            DBSecurityGroupDescription="sim2real overly-permissive probe",
            Tags=_TAGS,
        )
        code = None
    except ClientError as exc:
        code = exc.response["Error"]["Code"]

    subnet_group = _network_db_subnet_group(ctx, rds)
    if code in ("DBSecurityGroupNotSupported", "DBSecurityGroupNotSupportedFault"):
        # Effect absent: the rejected group must not actually exist.
        groups = rds.describe_db_security_groups()["DBSecurityGroups"]
        assert sg_name not in {g["DBSecurityGroupName"] for g in groups}, (
            "a DB security group was created despite the CreateDBSecurityGroup call being rejected"
        )
    else:
        # Some accounts/regions still accept CreateDBSecurityGroup; the group must then be
        # refused when attached to a VPC-launched DB instance.
        assert code is None, f"unexpected error creating DB security group: {code!r}"
        ctx.on_cleanup(lambda: rds.delete_db_security_group(DBSecurityGroupName=sg_name))

        instance_id = ctx.unique_name("sim2real-dbsginst-")
        use_error = _client_error(
            lambda: rds.create_db_instance(
                DBInstanceIdentifier=instance_id,
                Engine="postgres",
                DBInstanceClass="db.t3.micro",
                AllocatedStorage=20,
                MasterUsername="s2radmin",
                MasterUserPassword="Aa1" + "Sim2realProbe9",
                DBSecurityGroups=[sg_name],
                PubliclyAccessible=False,
                Tags=_TAGS,
                DBSubnetGroupName=subnet_group,
            )
        )
        assert use_error["Code"] == "InvalidParameterCombination", f"unexpected error {use_error!r}"
        assert use_error["Message"] == _USE_MESSAGE, f"unexpected message {use_error['Message']!r}"
        described_error = _client_error(
            lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        )
        assert described_error["Code"] == "DBInstanceNotFound", (
            f"instance was created despite the rejected CreateDBInstance call: {described_error!r}"
        )
        assert described_error["Message"] == f"DBInstance {instance_id} not found.", (
            f"unexpected message {described_error['Message']!r}"
        )

    # Positive control: an unrelated, supported create call succeeds.
    pg_name = ctx.unique_name("sim2real-dbpg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily="postgres16",
        Description="sim2real overly-permissive positive control",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    created = rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)["DBParameterGroups"]
    assert len(created) == 1 and created[0]["DBParameterGroupName"] == pg_name, (
        f"expected exactly one parameter group named {pg_name!r}, got {created!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A success raises: AWS refuses this call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"AWS refuses this call, but it succeeded and returned {result!r}")


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
