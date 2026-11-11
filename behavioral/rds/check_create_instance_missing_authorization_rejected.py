"""create-instance-missing-authorization-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

import secrets
import string

from behavioral_harness import tags

CHECK = "create-instance-missing-authorization-rejected"
GROUP = "error-semantics"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance naming a DB security group with no authorized ingress in DBSecurityGroups is
    rejected with InvalidParameterCombination and creates no instance."""
    rds = ctx.client("rds")
    sg_name = ctx.unique_name("sim2real-authsg-")

    rds.create_db_security_group(
        DBSecurityGroupName=sg_name,
        DBSecurityGroupDescription="sim2real AuthorizationNotFoundFault prerequisite probe",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_security_group(DBSecurityGroupName=sg_name))
    groups = rds.describe_db_security_groups(DBSecurityGroupName=sg_name)["DBSecurityGroups"]
    assert len(groups) == 1 and groups[0]["IPRanges"] == [] and groups[0]["EC2SecurityGroups"] == [], (
        f"expected one DB security group {sg_name!r} with no authorized ingress, got {groups!r}"
    )

    instance_id = ctx.unique_name("sim2real-authinst-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    code, message = _client_error(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=instance_id,
            Engine="postgres",
            DBInstanceClass="db.t3.micro",
            AllocatedStorage=20,
            MasterUsername="s2radmin",
            MasterUserPassword=_rand_password(),
            DBSecurityGroups=[sg_name],
            PubliclyAccessible=False,
            DBSubnetGroupName=subnet_group,
        )
    )
    assert code == "InvalidParameterCombination", f"unexpected error code {code!r}"
    assert message == (
        "DB Security Groups can only be associated with VPC DB Instances using API versions "
        "2012-01-15 through 2012-09-17."
    ), f"unexpected error message {message!r}"

    # Effect absent: the rejected CreateDBInstance call must not have created an instance.
    code, message = _client_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id))
    assert code == "DBInstanceNotFound", (
        f"instance was created despite the rejected CreateDBInstance call: {code!r}"
    )
    assert message == f"DBInstance {instance_id} not found.", f"unexpected error message {message!r}"

    # Positive control (same file): neither rejection above is evidence that this account's RDS
    # control plane is broadly broken -- an unrelated, currently-supported CREATE call succeeds
    # normally.
    pg_name = ctx.unique_name("sim2real-authpg-")
    rds.create_db_parameter_group(
        DBParameterGroupName=pg_name,
        DBParameterGroupFamily="postgres16",
        Description="sim2real AuthorizationNotFoundFault positive control",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=pg_name))
    created = rds.describe_db_parameter_groups(DBParameterGroupName=pg_name)["DBParameterGroups"]
    assert len(created) == 1 and created[0]["DBParameterGroupName"] == pg_name, (
        f"positive control failed: expected 1 parameter group named {pg_name!r}, got {created!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError `fn` raises; AssertionError when it succeeds."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


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
