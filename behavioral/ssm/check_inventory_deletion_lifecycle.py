"""inventory-deletion-lifecycle."""
from __future__ import annotations

import datetime
import json
import time

from behavioral_harness import tags

CHECK = "inventory-deletion-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """DeleteInventory of a custom type written on a managed node is reported, with its id and
    terminal status, by DescribeInventoryDeletions, after which the schema is unknown."""
    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    ec2_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not ec2_vpcs:
        raise AssertionError(
            "No shared network VPC in this account/region to launch a managed EC2 node "
            "into; PutInventory needs a real, running managed node."
        )
    vpc_id = ec2_vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("Shared network has no subnets to launch into.")
    subnet_id = subnets[0]["SubnetId"]

    role_name = ctx.unique_name("sim2real-inv-role-")[:64]
    profile_name = ctx.unique_name("sim2real-inv-prof-")[:128]
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn=managed_policy_arn
        ))
    )
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _safe_delete_instance_profile(iam, profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        ))
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    instance_id = _retry_on_profile_propagation(
        lambda: ec2.run_instances(
            ImageId=ami_id,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-inv-node-")}],
                }
            ],
        )["Instances"][0]["InstanceId"]
    )
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _poll_until(
        lambda: _describe_instance_state(ec2, instance_id),
        lambda state: state == "running",
        timeout_s=180.0,
        interval_s=5.0,
    )

    _poll_until(
        lambda: _ping_status(ssm, instance_id),
        lambda status: status == "Online",
        timeout_s=420.0,
        interval_s=10.0,
    )

    type_name = f"Custom:{ctx.unique_name('sim2realSsmInv')}"
    capture_time = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_name,
                "SchemaVersion": "1.0",
                "CaptureTime": capture_time,
                "Content": [{"Key": "behavioral-check"}],
            }
        ],
    )

    _poll_until(
        lambda: _schema_exists(ssm, type_name),
        lambda exists: exists,
        timeout_s=90.0,
        interval_s=5.0,
    )

    deletion = ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema")
    deletion_id = deletion["DeletionId"]
    assert deletion["TypeName"] == type_name, (
        f"DeleteInventory echoed TypeName={deletion['TypeName']!r}, expected {type_name!r}"
    )
    # Real AWS answers 0 or 1 here (the summary can be taken before the item is counted).
    assert deletion["DeletionSummary"]["TotalCount"] in (1, 0), (
        "expected DeletionSummary.TotalCount 1 (or 0) for a type with a single "
        f"instance's data, got {deletion['DeletionSummary']!r}"
    )

    status = _poll_until(
        lambda: ssm.describe_inventory_deletions(DeletionId=deletion_id)[
            "InventoryDeletions"
        ][0],
        lambda item: item["LastStatus"] == "Complete",
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert status["TypeName"] == type_name, (
        f"DescribeInventoryDeletions reported TypeName={status['TypeName']!r}, "
        f"expected {type_name!r}"
    )
    assert status["LastStatus"] == "Complete", (
        f"expected the deletion to reach LastStatus=Complete, got "
        f"{status['LastStatus']!r}: {status}"
    )

    # DeleteSchema was requested, so the terminal Complete status must mean the
    # schema itself -- not just the deletion job -- is gone: an independent read
    # through get_inventory_schema (not describe_inventory_deletions) must now
    # report it unknown, exactly like an instance that never wrote this type.
    _poll_until(
        lambda: not _schema_exists(ssm, type_name),
        lambda gone: gone,
        timeout_s=60.0,
        interval_s=5.0,
    )


def _schema_exists(ssm, type_name):
    from botocore.exceptions import ClientError

    try:
        result = ssm.get_inventory_schema(TypeName=type_name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidTypeNameException":
            return False
        raise
    return any(s["TypeName"] == type_name for s in result.get("Schemas", []))


def _describe_instance_state(ec2, instance_id):
    from botocore.exceptions import ClientError

    try:
        return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
            "Instances"
        ][0]["State"]["Name"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return None
        raise


def _ping_status(ssm, instance_id):
    page = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
    )
    infos = page.get("InstanceInformationList", [])
    if not infos:
        return None
    return infos[0].get("PingStatus")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _retry_on_profile_propagation(fn, timeout_s=90.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "").lower()
            if code == "InvalidParameterValue" and "invalid iam instance profile" in msg:
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchEntity", "LimitExceeded"):
            raise


def _safe_delete_role(iam, role_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_instance_profile(iam, profile_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
