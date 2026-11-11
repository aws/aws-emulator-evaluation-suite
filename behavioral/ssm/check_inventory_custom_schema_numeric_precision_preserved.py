"""inventory-custom-schema-numeric-precision-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "inventory-custom-schema-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["ssm"]

_SSM_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_NUMERIC_VALUE = "1234567890.123456789"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """Numeric custom-inventory values written via PutInventory come back from
    ListInventoryEntries as the exact same strings (Content is stored verbatim)."""
    ssm = ctx.client("ssm")
    profile_name = _create_ssm_instance_profile(ctx)
    instance_id = _launch_ssm_instance(ctx, profile_name)
    _wait_for_managed_instance_online(ctx, instance_id, timeout_s=600.0)

    type_name = "Custom:Sim2RealPrecision"
    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_name,
                "SchemaVersion": "1.0",
                "CaptureTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "Content": [{"NumericValue": _NUMERIC_VALUE, "Id": "1"}],
            }
        ],
    )

    matching = _poll_for_entry(ssm, instance_id, type_name, entry_id="1", timeout_s=90.0)
    assert matching["NumericValue"] == _NUMERIC_VALUE, (
        f"numeric precision was altered: expected {_NUMERIC_VALUE!r}, got {matching['NumericValue']!r}"
    )


# ===== helpers =====
def _poll_for_entry(ssm, instance_id: str, type_name: str, *, entry_id: str, timeout_s: float) -> dict:
    """A just-defined custom TypeName first answers InvalidTypeNameException, then an empty
    Entries list, before the written item is visible. Bounded retry on both; any other
    failure propagates."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_entries: list = []
    while time.monotonic() < deadline:
        try:
            last_entries = ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name)["Entries"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTypeNameException":
                raise
            time.sleep(3.0)
            continue
        matching = [e for e in last_entries if e.get("Id") == entry_id]
        if matching:
            return matching[0]
        time.sleep(3.0)
    raise AssertionError(
        f"inventory entry Id={entry_id!r} for {type_name} never became visible within {timeout_s}s "
        f"(last Entries={last_entries!r})"
    )


def _create_ssm_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ssm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _ignore(iam.delete_role, RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: _ignore(iam.detach_role_policy, RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY_ARN))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: _ignore(iam.delete_instance_profile, InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _ignore(iam.remove_role_from_instance_profile, InstanceProfileName=role_name, RoleName=role_name)
    )
    return role_name


def _launch_ssm_instance(ctx, profile_name: str) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-ssm-inv-")

    # A new instance profile is refused as InvalidParameterValue until IAM propagates it.
    left = ctx.time_left()
    deadline = time.monotonic() + (90.0 if left is None else min(90.0, left))
    while True:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue" or time.monotonic() >= deadline:
                raise
            time.sleep(2)

    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _ignore(ec2.terminate_instances, InstanceIds=[instance_id]))
    return instance_id


def _wait_for_managed_instance_online(ctx, instance_id: str, *, timeout_s: float) -> None:
    ssm = ctx.client("ssm")

    def probe():
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        return resp[0]["PingStatus"] if resp else None

    deadline = time.monotonic() + timeout_s
    status = probe()
    while time.monotonic() < deadline:
        status = probe()
        if status == "Online":
            return
        time.sleep(2)
    raise AssertionError(f"instance {instance_id} never reached PingStatus=Online (last={status!r})")


def _ignore(fn, **kwargs) -> None:
    try:
        fn(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
