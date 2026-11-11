"""resource-compliance-summary-reflects-resource-state."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-compliance-summary-reflects-resource-state"
GROUP = "state-machine"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListResourceComplianceSummaries reports COMPLIANT for a node with only COMPLIANT items and
    NON_COMPLIANT for a node with any NON_COMPLIANT item (the worst item status wins)."""
    ssm = ctx.client("ssm")
    # ManagedInstance is the only supported ResourceType and each ResourceId must be a real,
    # registered managed node, so two are provisioned.
    resource_compliant, resource_noncompliant = _provision_connected_targets(ctx, count=2)

    # Accounts have a cumulative cap on distinct Custom: ComplianceType names and no API frees
    # a slot, so an existing one is reused; summaries are per resource, so reuse is safe.
    compliance_type = _pick_reusable_custom_compliance_type(ssm, ctx)

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

    ssm.put_compliance_items(
        ResourceId=resource_compliant,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type,
        ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
        Items=[{"Id": "a1", "Severity": "LOW", "Status": "COMPLIANT"}],
    )
    ssm.put_compliance_items(
        ResourceId=resource_noncompliant,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type,
        ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
        Items=[{"Id": "b1", "Severity": "CRITICAL", "Status": "NON_COMPLIANT"}],
    )

    def _probe() -> dict[str, dict[str, Any]]:
        resp = ssm.list_resource_compliance_summaries(
            Filters=[{"Key": "ComplianceType", "Values": [compliance_type]}]
        )
        return {
            entry["ResourceId"]: entry
            for entry in resp["ResourceComplianceSummaryItems"]
        }

    by_resource = _poll_until(
        _probe,
        lambda d: resource_compliant in d and resource_noncompliant in d,
        timeout_s=_budget_s(ctx, 30.0),
        interval_s=2.0,
        ctx=ctx,
    )

    assert by_resource[resource_compliant]["Status"] == "COMPLIANT", (
        f"expected Status=COMPLIANT for {resource_compliant}, got "
        f"{by_resource[resource_compliant]['Status']!r}"
    )
    assert by_resource[resource_noncompliant]["Status"] == "NON_COMPLIANT", (
        f"expected Status=NON_COMPLIANT for {resource_noncompliant}, got "
        f"{by_resource[resource_noncompliant]['Status']!r}"
    )


def _pick_reusable_custom_compliance_type(ssm, ctx) -> str:
    """Return an existing Custom: sub-type of AWS:ComplianceItem, minting one if none exists.

    ComplianceType allows only alphanumerics after "Custom:", so the minted name drops hyphens."""
    resp = ssm.get_inventory_schema(TypeName="AWS:ComplianceItem", SubType=True)
    for schema in resp.get("Schemas", []):
        name = schema.get("TypeName", "")
        if name.startswith("Custom:"):
            return name
    return "Custom:" + ctx.unique_name("sim2real").replace("-", "")


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_running(ec2, instance_ids, timeout_s: float, ctx=None) -> None:
    """Poll every 2 s until every instance is running; fails on a dead-end state or the deadline."""
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
        if len(states) == len(instance_ids) and all(s == "running" for s in states.values()):
            return
        assert not any(s in ("shutting-down", "terminated", "stopping", "stopped") for s in states.values()), (
            f"instances {list(instance_ids)} reached {states!r} instead of running")
        if time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
            raise TimeoutError("instances reaching running: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"instances {list(instance_ids)} not running in time: {states!r}")
        time.sleep(2.0)


def _provision_connected_targets(ctx, count: int = 1) -> list[str]:
    """Launch `count` EC2 instances with an AmazonSSMManagedInstanceCore instance profile and
    return their InstanceIds once all are Online in Systems Manager."""
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
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
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

    _wait_running(ec2, instance_ids, _budget_s(ctx, 600.0), ctx=ctx)

    deadline = time.monotonic() + _budget_s(ctx, 600.0)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
