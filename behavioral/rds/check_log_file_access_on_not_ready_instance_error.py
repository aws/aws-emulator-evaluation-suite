"""log-file-access-on-not-ready-instance-error."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "log-file-access-on-not-ready-instance-error"
GROUP = "error-semantics"
SERVICES = ["rds"]

_TAGS = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a new instance is 'creating', DescribeDBLogFiles and DownloadDBLogFilePortion fail with
    the same DBInstanceNotFound fault a nonexistent identifier gets, and both succeed on the same
    instance once it is available."""
    instance_id = ctx.unique_name("sim2real-inst-")
    rds = ctx.client("rds")
    subnet_group = _private_subnet_group(ctx)

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real!Pwd01",
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        DBSubnetGroupName=subnet_group,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_and_wait(rds, instance_id))

    # The check holds the in-progress window itself: the instance it just created takes minutes
    # to provision, and the log calls are sent before the first wait.
    status = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
        "DBInstanceStatus"
    ]
    assert status == "creating", f"expected the freshly created instance to still be 'creating', got {status!r}"

    # The REST log endpoint reports a still-creating instance with the same "not found"
    # fault as an identifier that never existed (DBInstanceNotReady is for paused Serverless v2).
    code_describe, msg_describe = _error(lambda: rds.describe_db_log_files(DBInstanceIdentifier=instance_id))
    code_download, msg_download = _error(
        lambda: rds.download_db_log_file_portion(
            DBInstanceIdentifier=instance_id, LogFileName="error/postgresql.log"
        )
    )
    # Contrast/control: a genuinely nonexistent instance gets the identical fault code; only the
    # message wording differs between "still creating" and "never existed".
    bogus_id = ctx.unique_name("sim2real-nope-")
    code_missing, msg_missing = _error(lambda: rds.describe_db_log_files(DBInstanceIdentifier=bogus_id))

    observed = (code_describe, code_download, code_missing)
    assert observed == ("DBInstanceNotFound",) * 3, (
        f"expected DescribeDBLogFiles/DownloadDBLogFilePortion on the not-yet-ready instance and "
        f"DescribeDBLogFiles on a never-existed identifier to fail with DBInstanceNotFound, got {observed!r}"
    )
    messages = (msg_describe, msg_download, msg_missing)
    expected = (
        f"DBInstance {instance_id} not found.",
        f"DBInstance {instance_id} not found.",
        f"DBInstance not found: {bogus_id}",
    )
    assert messages == expected, f"expected messages {expected!r}, got {messages!r}"

    # Positive control: the same operation on the same instance succeeds once it is ready.
    _wait_for_instance_status(ctx, instance_id, "available", timeout_s=1200)
    resp = rds.describe_db_log_files(DBInstanceIdentifier=instance_id)
    assert isinstance(resp.get("DescribeDBLogFiles"), list), (
        f"expected DescribeDBLogFiles to succeed with a log-file list once the instance is "
        f"available, got response keys {list(resp.keys())!r}"
    )




def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` must raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
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
        CidrBlock="10.85.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}]
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
            VpcId=vpc_id, CidrBlock=f"10.85.{index}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _retry_delete(
            lambda: ec2.delete_subnet(SubnetId=s), "InvalidSubnetID.NotFound"))
        subnet_ids.append(subnet_id)
    name = ctx.unique_name("sim2real-inst-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real log-file check",
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


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float = 15.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _wait_for_instance_status(ctx, instance_id: str, status: str, *, timeout_s: float) -> None:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
            "DBInstanceStatus"
        ]

    _poll_until(probe, lambda s: s == status, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
