"""reboot-instance-before-available-rejected."""
from __future__ import annotations

import random
import string
import time

from behavioral_harness import tags

CHECK = "reboot-instance-before-available-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_TAGS = [{"Key": "sim2real", "Value": "reboot-instance-before-available-rejected"}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RebootDBInstance on an instance still 'creating' is rejected with InvalidDBInstanceState and does
    not move it to 'rebooting'; once available, the same reboot succeeds."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-rds-rbt-")
    password = _rds_password()
    subnet_group = _private_subnet_group(ctx)

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="sim2real",
        MasterUserPassword=password,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        MultiAZ=False,
        PubliclyAccessible=False,
        DBSubnetGroupName=subnet_group,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, instance_id))

    # The check holds the in-progress window itself: the instance it just created takes minutes
    # to provision, and the reboot is sent before the first wait.
    state = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]["DBInstanceStatus"]
    assert state == "creating", f"expected the freshly created instance to still be 'creating', got {state!r}"

    code, message = _error(lambda: rds.reboot_db_instance(DBInstanceIdentifier=instance_id))
    assert code == "InvalidDBInstanceState", f"expected InvalidDBInstanceState, got {code}"
    expected = (
        "Can only reboot db instances with state in: available, storage-optimization, "
        "storage-initialization, incompatible-credentials, incompatible-parameters.  "
        f"Instance {instance_id} has state: {state}."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected reboot never flips the instance to 'rebooting'
    after_reject = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert after_reject["DBInstanceStatus"] in ("creating", "backing-up", "available"), (
        f"reboot should have had no effect, got status {after_reject['DBInstanceStatus']!r}"
    )
    assert after_reject["DBInstanceStatus"] != "rebooting"

    # --- positive control: reboot succeeds once the instance is actually available ---
    _wait_for_instance_status(ctx, instance_id, {"available"}, timeout_s=1200, interval_s=15)
    rds.reboot_db_instance(DBInstanceIdentifier=instance_id)
    final = _wait_for_instance_status(ctx, instance_id, {"available"}, timeout_s=600, interval_s=10)
    assert final["DBInstanceStatus"] == "available"


def _rds_password() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=24)) + "9Aa"


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` must raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_delete(fn, *tolerated_codes, timeout_s=900, interval_s=20):
    """Delete, retrying while a dependency still holds it; a tolerated code means already gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in tolerated_codes:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"delete not completed, last error {code!r}") from exc
        time.sleep(interval_s)


def _private_subnet_group(ctx) -> str:
    """A dedicated VPC with private subnets in two AZs and a DB subnet group over them."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.84.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    zones = ec2.describe_availability_zones(Filters=[
        {"Name": "state", "Values": ["available"]},
        {"Name": "zone-type", "Values": ["availability-zone"]},
    ])["AvailabilityZones"]
    azs = sorted(z["ZoneName"] for z in zones)
    assert len(azs) >= 2, f"a DB subnet group needs 2 AZs; {ctx.region} offered {azs!r}"
    subnet_ids = []
    for index, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.84.{index}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _retry_delete(
            lambda: ec2.delete_subnet(SubnetId=s), "InvalidSubnetID.NotFound"))
        subnet_ids.append(subnet_id)
    name = ctx.unique_name("sim2real-rds-rbt-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real reboot check",
        SubnetIds=subnet_ids, Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name), "DBSubnetGroupNotFoundFault"))
    return name


def _delete_instance_and_wait(rds, instance_id, *, timeout_s=1500):
    """Delete the instance (retrying while its state refuses it) and wait until it is gone, so the
    subnet group, subnets and VPC registered before it can be deleted after it."""
    from botocore.exceptions import ClientError

    _retry_delete(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True),
        "DBInstanceNotFound", timeout_s=900,
    )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
                return
            raise
        time.sleep(20)
    raise RuntimeError(f"DB instance {instance_id} still present after {timeout_s}s")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_for_instance_status(ctx, instance_id, target_statuses, *, timeout_s=900.0, interval_s=15.0):
    rds = ctx.client("rds")

    def _probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    return _poll_until(
        _probe, lambda i: i["DBInstanceStatus"] in target_statuses, timeout_s=timeout_s, interval_s=interval_s
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
