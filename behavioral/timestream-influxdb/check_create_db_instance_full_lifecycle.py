"""create-db-instance-full-lifecycle."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "create-db-instance-full-lifecycle"
GROUP = "state"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDbInstance goes CREATING -> AVAILABLE with an endpoint and an auth secret ARN;
    after DeleteDbInstance it reads DELETED or not found, and RebootDbInstance on its id fails with
    ResourceNotFoundException "The DB instance with db id does not exist"."""
    net = _ensure_network(ctx)
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-lifecycle-")
    created = influx.create_db_instance(
        name=name,
        password=secrets.token_hex(12),
        dbInstanceType="db.influx.medium",
        vpcSubnetIds=net["subnet_ids"],
        vpcSecurityGroupIds=[net["security_group_id"]],
        allocatedStorage=20,
        dbStorageType="InfluxIOIncludedT1",
        deploymentType="SINGLE_AZ",
        tags={"sim2real:managed": "true"},
    )
    instance_id = created["id"]
    assert created["status"] == "CREATING", (
        f"expected initial status CREATING, got {created['status']!r}"
    )
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, instance_id))

    final = _poll_until(
        lambda: influx.get_db_instance(identifier=instance_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert final["status"] == "AVAILABLE", (
        f"instance reached terminal status {final['status']!r} instead of AVAILABLE"
    )
    assert final["endpoint"], f"expected a non-empty endpoint, got {final.get('endpoint')!r}"
    assert final["influxAuthParametersSecretArn"], (
        f"expected a non-empty influxAuthParametersSecretArn, got "
        f"{final.get('influxAuthParametersSecretArn')!r}"
    )

    influx.delete_db_instance(identifier=instance_id)
    _poll_until(
        lambda: _describe_or_none(influx, instance_id),
        lambda r: r is None or r["status"] == "DELETED",
        timeout_s=1200,
        interval_s=20,
    )

    # The delete is already asserted above via the independent read; also prove the dead
    # id is unusable, not merely absent from a status read.
    code, message = _error_code(lambda: influx.reboot_db_instance(identifier=instance_id))
    assert code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted instance to fail with ResourceNotFoundException, "
        f"got {code!r}"
    )
    assert message == "The DB instance with db id does not exist", message


def _describe_or_none(influx, instance_id):
    from botocore.exceptions import ClientError

    try:
        return influx.get_db_instance(identifier=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_instance_if_present(ctx, instance_id):
    from botocore.exceptions import ClientError

    influx = ctx.client("timestream-influxdb")
    try:
        influx.delete_db_instance(identifier=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to provision Timestream for InfluxDB "
            "networking prerequisites (would need a custom VPC/subnet/route-table setup)"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if len(subnets) < 2:
        raise AssertionError("shared network does not have at least 2 shared-network subnets")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sg_name = ctx.unique_name("sim2real-influxdb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real timestream-influxdb behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            }
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "security_group_id": sg_id}


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
