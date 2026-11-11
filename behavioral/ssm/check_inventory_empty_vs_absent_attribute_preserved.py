"""inventory-empty-vs-absent-attribute-preserved."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inventory-empty-vs-absent-attribute-preserved"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """ListInventoryEntries preserves an explicit empty-string attribute value exactly and
    never fabricates a key that a custom type never declared."""
    ssm = ctx.client("ssm")
    instance_id = _provision_ssm_managed_instance(ctx)
    # A custom type's schema is fixed by its first item and enforced on later ones, so
    # "empty string" and "never declared" can only be compared across two types.
    type_with_empty = "Custom:" + ctx.unique_name("Sim2RealInvA").replace("-", "")
    type_without_attr = "Custom:" + ctx.unique_name("Sim2RealInvB").replace("-", "")

    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_with_empty,
                "SchemaVersion": "1.0",
                "CaptureTime": _capture_time(),
                "Content": [{"Attr1": "value1", "Attr2": ""}],
            }
        ],
    )
    ssm.put_inventory(
        InstanceId=instance_id,
        Items=[
            {
                "TypeName": type_without_attr,
                "SchemaVersion": "1.0",
                "CaptureTime": _capture_time(),
                "Content": [{"Attr1": "value2"}],
            }
        ],
    )

    # GetInventorySchema must confirm the type is registered before ListInventoryEntries is
    # polled for it: real AWS answers ListInventoryEntries for a not-yet-registered TypeName
    # with InvalidTypeNameException rather than an empty list, so probing it directly would
    # crash the poll on the first, pre-registration attempt instead of retrying.
    _poll_until(
        lambda: _schema_registered(ssm, type_with_empty),
        lambda registered: registered,
        timeout_s=60,
        interval_s=3,
    )
    _poll_until(
        lambda: _schema_registered(ssm, type_without_attr),
        lambda registered: registered,
        timeout_s=60,
        interval_s=3,
    )

    entries_with_empty = _poll_until(
        lambda: ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_with_empty)[
            "Entries"
        ],
        lambda es: len(es) >= 1,
        timeout_s=300,
        interval_s=10,
    )
    entries_without_attr = _poll_until(
        lambda: ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_without_attr)[
            "Entries"
        ],
        lambda es: len(es) >= 1,
        timeout_s=300,
        interval_s=10,
    )
    assert len(entries_with_empty) == 1, (
        f"expected 1 entry for {type_with_empty}, got {len(entries_with_empty)}: {entries_with_empty!r}"
    )
    assert len(entries_without_attr) == 1, (
        f"expected 1 entry for {type_without_attr}, got {len(entries_without_attr)}: {entries_without_attr!r}"
    )
    entry_with_empty = entries_with_empty[0]
    entry_absent = entries_without_attr[0]

    assert entry_with_empty.get("Attr2") == "", (
        f"an explicitly-empty Attr2 was dropped or altered on read-back: {entry_with_empty!r}"
    )
    assert "Attr2" not in entry_absent, (
        f"an entry for a type that never declared Attr2 gained a fabricated key on read-back: "
        f"{entry_absent!r}"
    )


def _capture_time() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ===== helpers =====
def _schema_registered(ssm, type_name: str) -> bool:
    resp = ssm.get_inventory_schema(TypeName=type_name)
    return any(schema.get("TypeName") == type_name for schema in resp.get("Schemas", []))


def _teardown(fn, not_found: str, timeout_s: float = 60.0) -> None:
    """Run a teardown call; tolerate only its not-found code, retry DeleteConflict to a deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == not_found:
                return
            if code != "DeleteConflict" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _ssm_ami_id(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _provision_ssm_managed_instance(ctx, timeout_s: float = 420.0) -> str:
    """Launch an EC2 instance with the AmazonSSMManagedInstanceCore role and wait until it
    registers as an Online SSM managed node. Registers LIFO cleanup for instance/profile/role
    (terminate instance -> detach role from profile/delete profile -> detach policy/delete role)."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssm-role-")
    profile_name = ctx.unique_name("sim2real-ssm-prof-")
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup_role() -> None:
        _teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity")
        _teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")

    ctx.on_cleanup(_cleanup_role)

    iam.create_instance_profile(InstanceProfileName=profile_name)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)

    def _cleanup_profile() -> None:
        _teardown(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            ),
            "NoSuchEntity",
        )
        _teardown(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name), "NoSuchEntity")

    ctx.on_cleanup(_cleanup_profile)

    ami_id = _ssm_ami_id(ctx)
    name_tag = ctx.unique_name("sim2real-ssm-node-")
    instance_id = None
    last_err = None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                SubnetId=ctx.network().subnet_ids[0],
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidParameterValue":
                time.sleep(5)
                continue
            raise
    if instance_id is None:
        raise AssertionError(f"could not launch instance with IAM profile: {last_err}")

    def _cleanup_instance() -> None:
        _teardown(lambda: ec2.terminate_instances(InstanceIds=[instance_id]), "InvalidInstanceID.NotFound")
        ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup_instance)

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    def _ping_status():
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp["InstanceInformationList"]
        return infos[0]["PingStatus"] if infos else None

    status = _poll_until(_ping_status, lambda s: s == "Online", timeout_s=timeout_s, interval_s=15)
    if status != "Online":
        raise AssertionError(f"managed instance {instance_id} never reached Online ping status")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
