"""inventory-custom-schema-server-side-validation."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags


CHECK = "inventory-custom-schema-server-side-validation"
GROUP = "server-side"
SERVICES = ["ssm"]

_SSM_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """The first PutInventory for a new custom TypeName registers its schema; a later write
    dropping a registered attribute is rejected and leaves the schema unchanged, while a
    conforming write still succeeds."""
    # PutInventory rejects an InstanceId that is not a registered managed node
    # (InvalidInstanceId), so a real EC2 instance is registered as one.
    instance_id = _launch_ssm_managed_instance(ctx)
    ssm = ctx.client("ssm")

    type_name = "Custom:" + ctx.unique_name("SimBehav").replace("-", "")
    capture_time = _capture_time()

    # The custom type's schema outlives the instance; delete it with the check.
    ctx.on_cleanup(
        lambda: ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema")
    )
    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_name,
                "SchemaVersion": "2.0",
                "CaptureTime": capture_time,
                "Content": [{"Widget": "gizmo", "Stage": "PreProd"}],
            }
        ],
    )

    schema = _poll_for_schema(ssm, type_name, timeout_s=60.0)
    assert schema is not None, f"GetInventorySchema never reported {type_name!r}"
    assert schema["Version"] == "2.0", schema
    attr_names = {attr["Name"] for attr in schema["Attributes"]}
    assert attr_names == {"Widget", "Stage"}, attr_names

    # Break exactly one thing: keep the same SchemaVersion but drop the "Stage" attribute that
    # the registered schema above already committed to -- real AWS enforces the registered
    # schema's attribute set against subsequent writes rather than silently accepting anything.
    err = _error(
        lambda: ssm.put_inventory(
            InstanceId=instance_id,
            Items=[
                {
                    "TypeName": type_name,
                    "SchemaVersion": "2.0",
                    "CaptureTime": _capture_time(),
                    "Content": [{"Widget": "gizmo"}],
                }
            ],
        )
    )
    assert err["Code"] == "InvalidItemContentException", err
    expected_message = (
        "Custom inventory item doesn't match schema: input item [Widget ] but required "
        "[Widget Stage ]."
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # (b) effect absent: the registered schema is still exactly version 2.0 with both
    # attributes, unmoved by the rejected write.
    schema_after = _poll_for_schema(ssm, type_name, timeout_s=30.0)
    assert schema_after is not None and schema_after["Version"] == "2.0", schema_after
    attr_names_after = {attr["Name"] for attr in schema_after["Attributes"]}
    assert attr_names_after == {"Widget", "Stage"}, schema_after

    # (c) positive control: PutInventory using Content that still satisfies the registered
    # schema (both attributes present) keeps working.
    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_name,
                "SchemaVersion": "2.0",
                "CaptureTime": _capture_time(),
                "Content": [{"Widget": "sprocket", "Stage": "Prod"}],
            }
        ],
    )
    entries = _poll_for_entries(ssm, instance_id, type_name, timeout_s=120.0, expect_stage="Prod")
    assert any(e.get("Stage") == "Prod" for e in entries), entries


def _capture_time() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected success
    raises, so an emulator accepting what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, the call unexpectedly succeeded: {result!r}")


def _poll_for_schema(ssm, type_name: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.get_inventory_schema(TypeName=type_name)
        for schema in resp.get("Schemas", []):
            if schema.get("TypeName") == type_name:
                return schema
        time.sleep(3.0)
    return None


def _poll_for_entries(ssm, instance_id: str, type_name: str, timeout_s: float, expect_stage=None):
    deadline = time.monotonic() + timeout_s
    entries: list = []
    while time.monotonic() < deadline:
        resp = ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name)
        entries = resp.get("Entries", [])
        if entries and (expect_stage is None or any(e.get("Stage") == expect_stage for e in entries)):
            return entries
        time.sleep(3.0)
    return entries


def _wait_for_agent_online(
    ctx, instance_id: str, timeout_s: float = 600.0, interval_s: float = 15.0
) -> None:
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        if infos and infos[0].get("PingStatus") == "Online":
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"instance {instance_id} never reached PingStatus=Online (SSM Agent never registered)"
    )


def _launch_ssm_managed_instance(ctx, extra_tags=None) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    role_name = ctx.unique_name("sim2real-ssmrole-")
    trust = json.dumps(
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust, Tags=resource_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    )

    profile_name = ctx.unique_name("sim2real-ssmprof-")
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]

    tags = [{"Key": "Name", "Value": ctx.unique_name("sim2real-ssm-node-")}]
    if extra_tags:
        tags.extend(extra_tags)

    # IAM role/instance-profile propagation lag before EC2 will accept the profile:
    # bounded retry on the exact rejection code, never an unconditional sleep.
    instance_id = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValue":
                time.sleep(5.0)
                continue
            raise
    if instance_id is None:
        raise AssertionError("could not launch an EC2 instance for the SSM managed node")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _wait_for_agent_online(ctx, instance_id)
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
