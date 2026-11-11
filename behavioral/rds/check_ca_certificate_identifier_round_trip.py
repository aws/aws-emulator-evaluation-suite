"""ca-certificate-identifier-round-trip."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ca-certificate-identifier-round-trip"
GROUP = "representation"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"
_MANAGED_TAGS = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """A CACertificateIdentifier set via ModifyDBInstance is echoed back unchanged --
    both in the mutation response and on a subsequent, independent describe -- exercising
    exact identifier preservation rather than truncation/normalization of the CA name."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-cacert-")

    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        DBSubnetGroupName=_own_subnet_group(ctx),
        PubliclyAccessible=False,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))
    inst = _wait_for_instance_status(rds, db_id, "available", timeout_s=1800)
    current_ca = inst.get("CACertificateIdentifier")

    certs = rds.describe_certificates()["Certificates"]
    # rds-ca-ecc384-g1 is a DocumentDB-only CA, not assignable to an RDS postgres instance, so
    # candidates are restricted to the RSA family that is actually valid for this engine.
    candidates = sorted(
        c["CertificateIdentifier"]
        for c in certs
        if c["CertificateType"] == "CA"
        and c["CertificateIdentifier"] != current_ca
        and "rsa" in c["CertificateIdentifier"]
    )
    candidate = candidates[0] if candidates else None
    if candidate is None:
        raise AssertionError(
            "only one CA certificate identifier is available in this account/region, so a "
            "distinct CACertificateIdentifier cannot be exercised"
        )

    resp = rds.modify_db_instance(DBInstanceIdentifier=db_id, CACertificateIdentifier=candidate)
    pending = resp["DBInstance"].get("PendingModifiedValues", {})
    assert pending.get("CACertificateIdentifier") == candidate, (
        f"ModifyDBInstance response does not echo back the requested CACertificateIdentifier: "
        f"{pending!r}"
    )

    # Round-trip: an INDEPENDENT describe call (not the mutation's own response) must report
    # the exact same identifier, unchanged.
    inst_after = _describe_instance(rds, db_id)
    pending_after = inst_after.get("PendingModifiedValues", {})
    assert pending_after.get("CACertificateIdentifier") == candidate, (
        f"CACertificateIdentifier not preserved on subsequent describe: {pending_after!r}"
    )


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
    """Teardown: delete the instance with no final snapshot and wait until it is gone."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            _describe_instance(rds, db_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBInstanceNotFound":
                return
            raise
        time.sleep(20)
    raise AssertionError(f"teardown: DB instance {db_id} still exists after 1800s")


def _await_enis_clear(ec2, subnet_id, timeout_s=900, interval_s=15):
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


def _delete_with_retry(fn, timeout_s=300, interval_s=15):
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
