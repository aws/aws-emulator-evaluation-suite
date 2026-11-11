"""compliance-summary-aggregates-by-status."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compliance-summary-aggregates-by-status"
GROUP = "state-machine"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_COMPLIANCE_TYPE = "Custom:Sim2RealSummaryByStatus"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListComplianceSummaries CompliantCount, NonCompliantCount and the LOW/HIGH severity counts
    each rise by exactly 1 after items are put for one compliant and one non-compliant node."""
    ssm = ctx.client("ssm")
    # ManagedInstance is the only ResourceType, and each ResourceId must be a registered node.
    resource_compliant, resource_noncompliant = _provision_connected_targets(ctx, count=2)

    # Distinct Custom: ComplianceType names count against a cumulative account cap with no API to
    # free a slot, so every run reuses this check's one fixed name. It may still hold other runs'
    # data, so the assertions are on the delta the two new resources contribute.
    compliance_type = _COMPLIANCE_TYPE

    def _put(resource_id: str, status: str, severity: str) -> None:
        ssm.put_compliance_items(
            ResourceId=resource_id,
            ResourceType="ManagedInstance",
            ComplianceType=compliance_type,
            ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
            Items=[{"Id": "item-1", "Severity": severity, "Status": status}],
        )

    def _clear(resource_id: str) -> None:
        try:
            ssm.put_compliance_items(
                ResourceId=resource_id,
                ResourceType="ManagedInstance",
                ComplianceType=compliance_type,
                ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
                Items=[],
            )
        except ClientError as err:
            # The node is already deregistered, so it carries no compliance data to clear.
            if err.response["Error"]["Code"] != "InvalidResourceId":
                raise

    ctx.on_cleanup(lambda: _clear(resource_compliant))
    ctx.on_cleanup(lambda: _clear(resource_noncompliant))

    def _summary() -> dict[str, Any] | None:
        resp = ssm.list_compliance_summaries(
            Filters=[{"Key": "ComplianceType", "Values": [compliance_type]}]
        )
        for entry in resp["ComplianceSummaryItems"]:
            if entry["ComplianceType"] == compliance_type:
                return entry
        return None

    baseline = _summary()
    base_compliant = baseline["CompliantSummary"]["CompliantCount"] if baseline else 0
    base_noncompliant = baseline["NonCompliantSummary"]["NonCompliantCount"] if baseline else 0
    base_low = (
        baseline["CompliantSummary"]["SeveritySummary"]["LowCount"] if baseline else 0
    )
    base_high = (
        baseline["NonCompliantSummary"]["SeveritySummary"]["HighCount"] if baseline else 0
    )

    _put(resource_compliant, "COMPLIANT", "LOW")
    _put(resource_noncompliant, "NON_COMPLIANT", "HIGH")

    summary = _poll_until(
        _summary,
        lambda s: s is not None
        and s["CompliantSummary"]["CompliantCount"] >= base_compliant + 1
        and s["NonCompliantSummary"]["NonCompliantCount"] >= base_noncompliant + 1,
        timeout_s=_budget_s(ctx, 30.0),
        interval_s=2.0,
        ctx=ctx,
    )

    actual_compliant = summary["CompliantSummary"]["CompliantCount"]
    assert actual_compliant == base_compliant + 1, (
        f"expected CompliantCount to rise by exactly 1 from baseline {base_compliant}, "
        f"got {actual_compliant}"
    )
    actual_noncompliant = summary["NonCompliantSummary"]["NonCompliantCount"]
    assert actual_noncompliant == base_noncompliant + 1, (
        f"expected NonCompliantCount to rise by exactly 1 from baseline {base_noncompliant}, "
        f"got {actual_noncompliant}"
    )
    actual_low = summary["CompliantSummary"]["SeveritySummary"]["LowCount"]
    assert actual_low == base_low + 1, (
        f"expected CompliantSummary.SeveritySummary.LowCount to rise by exactly 1 from "
        f"baseline {base_low}, got {actual_low}"
    )
    actual_high = summary["NonCompliantSummary"]["SeveritySummary"]["HighCount"]
    assert actual_high == base_high + 1, (
        f"expected NonCompliantSummary.SeveritySummary.HighCount to rise by exactly 1 from "
        f"baseline {base_high}, got {actual_high}"
    )



def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0, ctx=None) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _provision_connected_targets(ctx, count: int = 1) -> list[str]:
    """Launch `count` EC2 instances with an SSM instance profile and wait until all register Online.
    Returns their InstanceIds."""
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
    deadline = time.monotonic() + _budget_s(ctx, 90)
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
            time.sleep(2)
    if not instance_ids:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))

    _wait_instances(ec2, instance_ids, "running", _budget_s(ctx, 600.0), ctx=ctx)

    deadline = time.monotonic() + _budget_s(ctx, 600)
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
        if _budget_spent(ctx):
            raise TimeoutError(f"instances {pending} reaching PingStatus=Online: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"instances {pending} never reached SSM PingStatus=Online in time")
    return instance_ids


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
