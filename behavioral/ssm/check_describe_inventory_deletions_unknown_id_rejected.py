"""describe-inventory-deletions-unknown-id-rejected."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-inventory-deletions-unknown-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """DescribeInventoryDeletions rejects a DeletionId that violates its UUID pattern with
    ValidationException rather than treating it as an empty query; a well-formed unissued id
    returns an empty list and a real DeletionId from DeleteInventory resolves."""
    ssm = ctx.client("ssm")

    # Overly-permissive boundary: a DeletionId that does not match the required UUID-like
    # pattern must be rejected, not silently treated as "no matching deletion".
    malformed_id = "not-a-valid-deletion-id"
    error = _error(lambda: ssm.describe_inventory_deletions(DeletionId=malformed_id))
    assert error["Code"] == "ValidationException", (
        f"expected DescribeInventoryDeletions to reject malformed DeletionId "
        f"{malformed_id!r} with ValidationException, got {error!r}"
    )
    assert error["Message"] == (
        f"1 validation error detected: Value '{malformed_id}' at 'deletionId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
    ), error["Message"]

    # Positive control 1: a syntactically valid but never-issued DeletionId is NOT an error --
    # AWS returns an empty list rather than InvalidDeletionIdException (empirical behavior).
    unknown_id = str(uuid.uuid4())
    unknown_resp = ssm.describe_inventory_deletions(DeletionId=unknown_id)
    assert unknown_resp["InventoryDeletions"] == [], (
        f"expected empty InventoryDeletions for a well-formed but unissued DeletionId, "
        f"got {unknown_resp['InventoryDeletions']}"
    )

    # Positive control 2: a real DeletionId, produced from a real, previously-registered
    # Custom: inventory type, must resolve. DeleteInventory requires the type to already
    # exist, so create it first via PutInventory against a real managed node.
    instance_id = _provision_connected_targets(ctx, count=1)[0]
    type_name = "Custom:" + ctx.unique_name("S2RDescOk").replace("-", "")

    def _cleanup() -> None:
        try:
            ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTypeNameException":
                raise

    ctx.on_cleanup(_cleanup)

    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_name,
                "SchemaVersion": "1.0",
                "CaptureTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Content": [{"TestKey": "TestValue"}],
            }
        ],
    )
    _poll_until(
        lambda: _try_list_entries(ssm, instance_id, type_name),
        lambda entries: entries is not None and len(entries) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )

    delete_resp = ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema")
    real_id = delete_resp["DeletionId"]

    describe_resp = ssm.describe_inventory_deletions(DeletionId=real_id)
    deletions = describe_resp["InventoryDeletions"]
    assert len(deletions) == 1
    assert deletions[0]["DeletionId"] == real_id
    assert deletions[0]["TypeName"] == type_name


# ===== helpers =====

def _try_list_entries(ssm, instance_id: str, type_name: str):
    try:
        resp = ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name)
        return resp.get("Entries", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidTypeNameException":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")



def _error(fn):
    """Call fn(); return its botocore error dict. An unexpected SUCCESS raises, because a
    target accepting what real AWS refuses must fail as an acceptance, not a code mismatch."""
    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {resp!r}")


def _provision_connected_targets(ctx, count: int = 1) -> list[str]:
    """Create an IAM role + instance profile with AmazonSSMManagedInstanceCore, launch `count`
    EC2 instances in one call, and wait until ALL register Online with Systems Manager. Returns
    the list of InstanceIds."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-behav-ssm-role-")
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    )

    profile_name = ctx.unique_name("sim2real-behav-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-behav-ssm-target-")

    instance_ids: list[str] = []
    last_err = None
    deadline = time.monotonic() + 90
    while not instance_ids and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=count,
                MaxCount=count,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterValueError",
            ):
                raise
            time.sleep(5)
    if not instance_ids:
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))

    ec2.get_waiter("instance_running").wait(InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    deadline = time.monotonic() + 600
    pending = set(instance_ids)
    while pending and time.monotonic() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": list(pending)}]
        )["InstanceInformationList"]
        online = {i["InstanceId"] for i in info if i.get("PingStatus") == "Online"}
        pending -= online
        if pending:
            time.sleep(2)
    if pending:
        raise AssertionError(f"instances {pending} never reached SSM PingStatus=Online in time")
    return instance_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
