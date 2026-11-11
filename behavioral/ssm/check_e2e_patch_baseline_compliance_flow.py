"""e2e-patch-baseline-compliance-flow."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-patch-baseline-compliance-flow"
GROUP = "e2e"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Compliance items put for a registered node roll up into its server-computed Patch summary
    (NON_COMPLIANT, one CRITICAL non-compliant item); a baseline still registered to a patch group cannot be deleted
    (ResourceInUseException) until it is deregistered, after which it is gone."""
    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    # PutComplianceItems rejects a ResourceId that is not a registered managed node
    # (InvalidResourceId), so a real EC2 instance is registered as one.
    resource_id = _provision_managed_node(ctx, ssm, ec2, iam)

    baseline_name = ctx.unique_name("sim2real-baseline-")
    patch_group = ctx.unique_name("sim2real-pg-")

    baseline_id = ssm.create_patch_baseline(
        Name=baseline_name,
        OperatingSystem="AMAZON_LINUX_2",
        ApprovalRules={
            "PatchRules": [
                {
                    "PatchFilterGroup": {
                        "PatchFilters": [{"Key": "CLASSIFICATION", "Values": ["Security"]}]
                    },
                    "ApproveAfterDays": 7,
                    "ComplianceLevel": "CRITICAL",
                }
            ]
        },
    )["BaselineId"]
    ctx.on_cleanup(lambda: _try_delete_baseline(ssm, baseline_id))

    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: _ignore(
            ssm.deregister_patch_baseline_for_patch_group,
            BaselineId=baseline_id,
            PatchGroup=patch_group,
        )
    )

    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType="ManagedInstance",
        ComplianceType="Patch",
        ExecutionSummary={
            "ExecutionTime": datetime.now(timezone.utc),
            "ExecutionId": "sim2real-exec-1",
            "ExecutionType": "Command",
        },
        Items=[
            {
                "Id": "KB0000001",
                "Title": "sim2real test patch",
                "Severity": "CRITICAL",
                "Status": "NON_COMPLIANT",
            }
        ],
    )

    summary = _poll_until(
        lambda: _resource_patch_summary(ssm, resource_id),
        _settled_noncompliant,
        timeout_s=45.0,
        interval_s=3.0,
    )
    noncompliant = summary["NonCompliantSummary"]
    assert noncompliant["SeveritySummary"]["CriticalCount"] == 1, (
        f"expected the node's Patch summary to count one CRITICAL non-compliant item after "
        f"PutComplianceItems, got {summary!r}"
    )
    assert summary["CompliantSummary"]["CompliantCount"] == 0, (
        f"expected the node's Patch summary to count no compliant item, got {summary!r}"
    )

    items = ssm.list_compliance_items(
        ResourceIds=[resource_id], Filters=[{"Key": "ComplianceType", "Values": ["Patch"]}]
    )["ComplianceItems"]
    matching = [i for i in items if i["Id"] == "KB0000001"]
    assert len(matching) == 1, (
        f"expected exactly one compliance item with Id 'KB0000001' for {resource_id!r}, "
        f"got {items!r}"
    )
    assert matching[0]["Status"] == "NON_COMPLIANT", (
        f"expected Status 'NON_COMPLIANT', got {matching[0]['Status']!r}: {matching[0]!r}"
    )
    assert matching[0]["Severity"] == "CRITICAL", (
        f"expected Severity 'CRITICAL', got {matching[0]['Severity']!r}: {matching[0]!r}"
    )

    # Negative: deleting the baseline while it is still registered to a patch group is
    # rejected, and the baseline is NOT removed by the failed attempt.
    in_use = _error(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id))
    assert in_use["Code"] == "ResourceInUseException", (
        f"expected DeletePatchBaseline on a baseline still registered to a patch group to "
        f"fail with ResourceInUseException, got {in_use!r}"
    )
    assert in_use["Message"] == (
        f"PatchBaseline to be deleted is used for Patch Group: {patch_group}"
    ), in_use["Message"]
    still_there = ssm.get_patch_baseline(BaselineId=baseline_id)
    assert still_there["BaselineId"] == baseline_id, (
        f"the rejected delete must not have removed the baseline; expected "
        f"{baseline_id!r}, got {still_there!r}"
    )

    # Positive control: once deregistered, deletion succeeds.
    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)
    ssm.delete_patch_baseline(BaselineId=baseline_id)
    gone = _error(lambda: ssm.get_patch_baseline(BaselineId=baseline_id))
    assert gone["Code"] == "DoesNotExistException", (
        f"expected GetPatchBaseline on the deleted baseline to fail with "
        f"DoesNotExistException, got {gone!r}"
    )
    assert gone["Message"] == "Patch Baseline to be retrieved does not exist.", gone["Message"]


def _error(fn: Any) -> dict:
    """Call fn(); return its ClientError error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn, **kwargs) -> None:
    fn(**kwargs)


def _try_delete_baseline(ssm, baseline_id: str) -> None:
    ssm.delete_patch_baseline(BaselineId=baseline_id)


def _resource_patch_summary(ssm, resource_id: str) -> dict | None:
    """The server-computed Patch summary of one managed node from ListResourceComplianceSummaries.

    The listing is account-wide; only this node's Patch row is read."""
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = ssm.list_resource_compliance_summaries(**kwargs)
        for item in page.get("ResourceComplianceSummaryItems", []):
            if item.get("ResourceId") == resource_id and item.get("ComplianceType") == "Patch":
                return item
        token = page.get("NextToken")
        if not token:
            return None


def _settled_noncompliant(summary) -> bool:
    """True once the node's Patch summary rolls up one NON_COMPLIANT CRITICAL item."""
    return (
        summary is not None
        and summary.get("Status") == "NON_COMPLIANT"
        and summary.get("NonCompliantSummary", {}).get("NonCompliantCount") == 1
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if not predicate(value):
        raise AssertionError(f"condition never satisfied, last value={value!r}")
    return value


def _provision_managed_node(ctx, ssm, ec2, iam) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "No shared network VPC in this account/region to launch a managed EC2 node "
            "into; PutComplianceItems needs a real, registered managed node."
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("Shared network has no subnets to launch into.")
    subnet_id = subnets[0]["SubnetId"]

    role_name = ctx.unique_name("sim2real-pb-role-")[:64]
    profile_name = ctx.unique_name("sim2real-pb-prof-")[:128]
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)))
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
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-pb-node-")}],
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
    return instance_id


def _describe_instance_state(ec2, instance_id):
    try:
        return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return None
        raise


def _ping_status(ssm, instance_id):
    page = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
    infos = page.get("InstanceInformationList", [])
    if not infos:
        return None
    return infos[0].get("PingStatus")


def _retry_on_profile_propagation(fn, timeout_s=90.0, interval_s=5.0):
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
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchEntity", "LimitExceeded"):
            raise


def _safe_delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_instance_profile(iam, profile_name):
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

