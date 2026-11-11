"""e2e-certificate-rotation-consequence-flow."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-certificate-rotation-consequence-flow"
GROUP = "e2e"
SERVICES = ["rds"]

_MANAGED_TAGS = [{"Key": "sim2real", "Value": "behav"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CA change without ApplyImmediately stays pending with the original CA still effective.

    After RebootDBInstance the original CA is still effective and the pending entry names the new CA.
    """
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-cacert-")
    password = _rand_password()
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        DBSubnetGroupName=_own_subnet_group(ctx),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, instance_id))
    instance = _wait_instance_status(ctx, instance_id, "available", timeout_s=1200)
    original_ca = instance["CACertificateIdentifier"]

    certs = rds.describe_certificates()["Certificates"]
    # rds-ca-ecc384-g1 is a DocumentDB-only CA (not valid for RDS engines like postgres), so
    # restrict candidates to the RSA family that's actually assignable on this engine.
    candidates = [
        c["CertificateIdentifier"]
        for c in certs
        if c["CertificateType"] == "CA"
        and c["CertificateIdentifier"] != original_ca
        and "rsa" in c["CertificateIdentifier"]
    ]
    if not candidates:
        raise AssertionError(f"no alternate RSA CA certificate to rotate to (only {original_ca!r} available)")
    new_ca = sorted(candidates)[0]

    rds.modify_db_instance(
        DBInstanceIdentifier=instance_id,
        CACertificateIdentifier=new_ca,
        ApplyImmediately=False,
    )

    # Pending, not yet effective: the current CA is unchanged and the pending value is set.
    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert instance["CACertificateIdentifier"] == original_ca, (
        "current CA changed before any reboot was issued"
    )
    pending = instance.get("PendingModifiedValues", {})
    assert pending.get("CACertificateIdentifier") == new_ca, (
        f"expected pending CA {new_ca!r}, got {pending.get('CACertificateIdentifier')!r}"
    )

    rds.reboot_db_instance(DBInstanceIdentifier=instance_id)
    _wait_instance_status(ctx, instance_id, "available", timeout_s=900)

    # A plain reboot does not apply the pending CA change on a default-version PostgreSQL
    # instance: the effective CA stays on the original and the pending entry is not cleared.
    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert instance["CACertificateIdentifier"] == original_ca, (
        f"effective CA after reboot was {instance['CACertificateIdentifier']!r}, expected the "
        f"reboot to leave the unsupported pending CA {new_ca!r} unapplied and stay on "
        f"{original_ca!r}"
    )
    pending_after = instance.get("PendingModifiedValues", {})
    assert pending_after.get("CACertificateIdentifier") == new_ca, (
        f"expected the unapplied pending CA {new_ca!r} to remain stuck after the reboot, got "
        f"{pending_after.get('CACertificateIdentifier')!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )



def _delete_instance(rds, instance_id) -> None:
    """Delete the instance with no final snapshot and wait until it is gone."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"teardown: DB instance {instance_id} still exists after 1800s")


def _await_enis_clear(ec2, subnet_id, timeout_s=900, interval_s=2):
    """Wait out RDS ENIs left in a subnet of this check's own VPC after the instance is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )["NetworkInterfaces"]
        if not enis:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"subnet {subnet_id} still has {len(enis)} ENI(s) after {timeout_s}s: "
                f"{[e['NetworkInterfaceId'] for e in enis]}"
            )
        time.sleep(interval_s)


def _delete_with_retry(fn, timeout_s=300, interval_s=2):
    """Run an EC2 delete, retrying DependencyViolation until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _own_subnet_group(ctx):
    """A DB subnet group over a two-AZ VPC this check creates; all of it registered for cleanup."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= 2, f"region {ctx.region!r} has only {len(azs)} available AZ(s); need 2"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.194.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.194.0.{i * 16}/28",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]

        def _drop_subnet(sid=subnet_id):
            _await_enis_clear(ec2, sid)
            _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=sid))

        ctx.on_cleanup(_drop_subnet)
        subnet_ids.append(subnet_id)
    name = ctx.unique_name("sim2real-behav-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
