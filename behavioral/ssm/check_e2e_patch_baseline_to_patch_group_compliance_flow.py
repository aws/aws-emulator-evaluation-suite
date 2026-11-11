"""e2e-patch-baseline-to-patch-group-compliance-flow."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-patch-baseline-to-patch-group-compliance-flow"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Registering a patch baseline to a patch group and putting compliance items yields a
    per-resource record and a server-computed NON_COMPLIANT Patch summary for that node; deregistering and deleting the
    baseline reverts the patch group to the OS default baseline."""
    ssm = ctx.client("ssm")
    baseline_name = ctx.unique_name("sim2real-baseline-")
    patch_group = ctx.unique_name("sim2real-pg-")
    os_name = "AMAZON_LINUX_2"

    approval_rules = {
        "PatchRules": [
            {
                "PatchFilterGroup": {
                    "PatchFilters": [{"Key": "CLASSIFICATION", "Values": ["Security"]}]
                },
                "ApproveAfterDays": 7,
            }
        ]
    }
    baseline_id = ssm.create_patch_baseline(
        Name=baseline_name, OperatingSystem=os_name, ApprovalRules=approval_rules
    )["BaselineId"]
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_patch_baseline(BaselineId=baseline_id)))

    ssm.register_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_patch_baseline_for_patch_group(
                BaselineId=baseline_id, PatchGroup=patch_group
            )
        )
    )

    mapping = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem=os_name
    )
    assert mapping["BaselineId"] == baseline_id, (
        f"expected GetPatchBaselineForPatchGroup({patch_group!r}) to resolve to the "
        f"just-registered baseline {baseline_id!r}, got {mapping!r}"
    )

    groups = ssm.describe_patch_groups()["Mappings"]
    assert any(
        m["PatchGroup"] == patch_group and m["BaselineIdentity"]["BaselineId"] == baseline_id
        for m in groups
    ), (
        f"expected DescribePatchGroups to list {patch_group!r} mapped to "
        f"{baseline_id!r}, got {groups!r}"
    )

    # A real, registered managed node -- but deliberately NOT tagged with "Patch Group" ==
    # patch_group, so the patch-group-state view below must not fabricate a membership for it.
    # PutComplianceItems requires a live, registered managed node as ResourceId.
    resource_id = _provision_ssm_managed_instance(ctx)
    exec_time = datetime.now(timezone.utc).replace(microsecond=0)
    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType="ManagedInstance",
        ComplianceType="Patch",
        ExecutionSummary={"ExecutionTime": exec_time, "ExecutionType": "Command"},
        Items=[
            {
                "Id": "KB0000001",
                "Title": "Sim2Real Test Patch",
                "Severity": "CRITICAL",
                "Status": "NON_COMPLIANT",
            }
        ],
    )

    summary = _poll_until(
        lambda: _resource_patch_summary(ssm, resource_id),
        _settled_noncompliant,
        timeout_s=_budget_s(ctx, 60),
        interval_s=2.0,
    )
    if not _settled_noncompliant(summary) and _budget_spent(ctx):
        raise TimeoutError("the node's Patch summary settling: the run budget ended first; not graded")
    assert _settled_noncompliant(summary), (
        f"expected the node's Patch summary to roll up one NON_COMPLIANT item after "
        f"PutComplianceItems, got {summary!r}"
    )
    assert summary["NonCompliantSummary"]["SeveritySummary"]["CriticalCount"] == 1, (
        f"expected the node's Patch summary to count one CRITICAL non-compliant item, "
        f"got {summary!r}"
    )

    # ListComplianceItems is eventually consistent with PutComplianceItems; poll until it lists.
    items = _poll_until(
        lambda: ssm.list_compliance_items(ResourceIds=[resource_id])["ComplianceItems"],
        lambda found: len(found) > 0,
        timeout_s=_budget_s(ctx, 60),
        interval_s=2.0,
    )
    if not items and _budget_spent(ctx):
        raise TimeoutError("the compliance item listing: the run budget ended first; not graded")
    assert len(items) == 1, (
        f"expected exactly one compliance item for {resource_id!r}, got {items!r}"
    )
    assert items[0]["Id"] == "KB0000001", (
        f"expected compliance item Id 'KB0000001', got {items[0]!r}"
    )
    assert items[0]["Status"] == "NON_COMPLIANT", (
        f"expected compliance item Status 'NON_COMPLIANT', got {items[0]!r}"
    )
    assert items[0]["Severity"] == "CRITICAL", (
        f"expected compliance item Severity 'CRITICAL', got {items[0]!r}"
    )

    # The instance was never tagged/registered as a member of this patch group, so the
    # patch-group-state view must not fabricate a membership for it.
    state = ssm.describe_patch_group_state(PatchGroup=patch_group)
    assert state["Instances"] == 0, (
        f"expected DescribePatchGroupState({patch_group!r}) to report 0 member "
        f"instances since {resource_id!r} was never tagged into the group, got {state!r}"
    )

    ssm.deregister_patch_baseline_for_patch_group(BaselineId=baseline_id, PatchGroup=patch_group)
    reverted = ssm.get_patch_baseline_for_patch_group(
        PatchGroup=patch_group, OperatingSystem=os_name
    )
    assert reverted["BaselineId"] != baseline_id, (
        f"expected GetPatchBaselineForPatchGroup({patch_group!r}) to revert to the OS "
        f"default after deregistration, still got {baseline_id!r}: {reverted!r}"
    )

    ssm.delete_patch_baseline(BaselineId=baseline_id)
    gone = _error(lambda: ssm.get_patch_baseline(BaselineId=baseline_id))
    assert gone["Code"] == "DoesNotExistException", (
        f"expected GetPatchBaseline on the deleted baseline {baseline_id!r} to fail "
        f"with DoesNotExistException, got {gone!r}"
    )
    assert gone["Message"] == "Patch Baseline to be retrieved does not exist.", gone["Message"]


# Teardown steps return only when the resource is already gone; any other failure raises.
_NOT_FOUND = ("DoesNotExistException", "NoSuchEntity", "InvalidInstanceID.NotFound")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in _NOT_FOUND:
            raise


def _error(fn) -> dict:
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


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


def _ssm_ami_id(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _provision_ssm_managed_instance(ctx, timeout_s: float = 420.0) -> str:
    """Launch an EC2 instance with the AmazonSSMManagedInstanceCore role and wait until it registers
    Online with SSM; registers cleanup for the instance, profile and role."""
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
    deadline = time.monotonic() + _budget_s(ctx, 120)
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
                time.sleep(2)
                continue
            raise
    if instance_id is None:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"could not launch instance with IAM profile: {last_err}")

    def _cleanup_instance() -> None:
        _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
        _safe(lambda: _wait_instances(ec2, [instance_id], "terminated", _budget_s(ctx, 600.0), strict=False))

    ctx.on_cleanup(_cleanup_instance)

    _wait_instances(ec2, [instance_id], "running", _budget_s(ctx, 600.0), ctx=ctx)

    def _ping_status():
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp["InstanceInformationList"]
        return infos[0]["PingStatus"] if infos else None

    status = _poll_until(_ping_status, lambda s: s == "Online", timeout_s=_budget_s(ctx, timeout_s), interval_s=2.0)
    if status != "Online":
        if _budget_spent(ctx):
            raise TimeoutError(f"instance {instance_id} reaching PingStatus=Online: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"managed instance {instance_id} never reached Online ping status")
    return instance_id


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_instances(ec2, instance_ids, want: str, timeout_s: float, *, strict: bool = True, ctx=None) -> None:
    """Poll every 1 s until every instance is in state want; a strict wait fails on a dead end."""
    dead = {"running": ("shutting-down", "terminated", "stopping", "stopped")}.get(want, ())
    deadline = time.monotonic() + timeout_s
    states = {}
    while True:
        try:
            reservations = ec2.describe_instances(InstanceIds=list(instance_ids))["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            reservations = []
        states = {i["InstanceId"]: i["State"]["Name"] for r in reservations for i in r["Instances"]}
        if len(states) == len(instance_ids) and all(s == want for s in states.values()):
            return
        if not strict:
            if time.monotonic() >= deadline:
                return
        else:
            assert not any(s in dead for s in states.values()), (
                f"instances {list(instance_ids)} reached {states!r} instead of {want!r}")
            if time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"instances reaching {want!r}: the run budget ended first; not graded")
            assert time.monotonic() < deadline, (
                f"instances {list(instance_ids)} not {want!r} in time: {states!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

