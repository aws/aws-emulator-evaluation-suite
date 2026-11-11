"""compliance-item-numeric-and-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compliance-item-numeric-and-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["ssm"]

_FALLBACK_COMPLIANCE_TYPE = "Custom:Sim2RealPrecision"
_SUMMARY_GRADED_TYPES = ("Custom:Sim2RealSummaryByStatus", "Custom:Sim2RealAggregation")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListComplianceItems returns the exact ExecutionTime and numeric-looking string Details
    values written by PutComplianceItems (no leading-zero or decimal-digit loss, no time shift).
    """
    ssm = ctx.client("ssm")
    # PutComplianceItems rejects a ResourceId that is not a registered, online managed node.
    resource_id = _provision_ssm_managed_instance(ctx)
    # A Custom: ComplianceType name is a permanent registration counted against an account-wide
    # cap with no API to release it, so a registered one is reused; every read is scoped to the
    # fresh managed node, which keeps runs apart.
    compliance_type = _pick_custom_compliance_type(ssm)
    exec_time = datetime(2023, 6, 15, 12, 34, 56, tzinfo=timezone.utc)

    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type,
        ExecutionSummary={
            "ExecutionTime": exec_time,
            "ExecutionId": "exec-sim2real-1",
            "ExecutionType": "Command",
        },
        Items=[
            {
                "Id": "item-1",
                "Title": "precision test item",
                "Severity": "HIGH",
                "Status": "NON_COMPLIANT",
                # Details keys must be attributes of the fixed AWS:ComplianceItem schema; an
                # unknown key is rejected with InvalidItemContentException.
                "Details": {
                    "CVEIds": "9.800000001",
                    "DocumentVersion": "00042",
                },
            }
        ],
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.put_compliance_items(
                ResourceId=resource_id,
                ResourceType="ManagedInstance",
                ComplianceType=compliance_type,
                ExecutionSummary={"ExecutionTime": exec_time},
                Items=[],
            )
        )
    )

    item = _poll_until(
        lambda: ssm.list_compliance_items(ResourceIds=[resource_id])["ComplianceItems"],
        lambda items: len(items) == 1,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert item is not None and len(item) == 1, f"expected exactly one compliance item, got {item}"
    item = item[0]

    assert item["ExecutionSummary"]["ExecutionTime"] == exec_time, (
        item["ExecutionSummary"]["ExecutionTime"],
        exec_time,
    )
    assert item["Details"]["CVEIds"] == "9.800000001", item["Details"]
    assert item["Details"]["DocumentVersion"] == "00042", item["Details"]


# Teardown steps return only when the resource is already gone; any other failure raises.
_NOT_FOUND = ("NoSuchEntity", "InvalidInstanceID.NotFound")


def _pick_custom_compliance_type(ssm) -> str:
    """Return a registered Custom: compliance sub-type, else one shared fallback name. Names whose
    account-wide summaries other checks grade by delta are never written."""
    resp = ssm.get_inventory_schema(TypeName="AWS:ComplianceItem", SubType=True)
    for schema in resp.get("Schemas", []):
        name = schema.get("TypeName", "")
        if name.startswith("Custom:") and not name.startswith(_SUMMARY_GRADED_TYPES):
            return name
    return _FALLBACK_COMPLIANCE_TYPE


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in _NOT_FOUND:
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _ssm_ami_id(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _provision_ssm_managed_instance(ctx, timeout_s: float = 420.0) -> str:
    """Launch an EC2 instance with the AmazonSSMManagedInstanceCore role and wait until it
    registers as an Online SSM managed node."""
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
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)

    iam.create_instance_profile(InstanceProfileName=profile_name)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)

    def _cleanup_profile() -> None:
        _safe(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        )
        _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

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
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
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
        _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
        _safe(lambda: ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}))

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

