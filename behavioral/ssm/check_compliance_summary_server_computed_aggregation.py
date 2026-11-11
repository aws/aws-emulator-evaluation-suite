"""compliance-summary-server-computed-aggregation."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "compliance-summary-server-computed-aggregation"
GROUP = "server-side"
SERVICES = ["ssm"]

_SSM_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListComplianceSummaries counts and per-severity breakdowns are aggregated server-side:
    one NON_COMPLIANT CRITICAL and one COMPLIANT MEDIUM write each raise their type's counts by one.
    """
    ssm = ctx.client("ssm")
    resource_id = _launch_ssm_managed_instance(ctx)

    # AWS rolls a resource's compliance up to one status per ComplianceType (any NON_COMPLIANT
    # item makes the record NON_COMPLIANT), so the two statuses need two distinct types.
    # Distinct Custom: ComplianceType names count against a cumulative account cap with no API to
    # free a slot, so every run reuses this check's two fixed names.
    compliance_type_noncompliant = "Custom:Sim2RealAggregationNonCompliant"
    compliance_type_compliant = "Custom:Sim2RealAggregationCompliant"

    def _summary(compliance_type: str):
        resp = ssm.list_compliance_summaries(
            Filters=[{"Key": "ComplianceType", "Values": [compliance_type]}]
        )
        for item in resp.get("ComplianceSummaryItems", []):
            if item.get("ComplianceType") == compliance_type:
                return item
        return None

    # The types may still carry other runs' data, so assert deltas.
    baseline_nc = _summary(compliance_type_noncompliant)
    base_noncompliant = (baseline_nc or {}).get("NonCompliantSummary", {}).get("NonCompliantCount", 0)
    base_critical = (
        (baseline_nc or {}).get("NonCompliantSummary", {}).get("SeveritySummary", {}).get("CriticalCount", 0)
    )
    baseline_c = _summary(compliance_type_compliant)
    base_compliant = (baseline_c or {}).get("CompliantSummary", {}).get("CompliantCount", 0)
    base_medium = (
        (baseline_c or {}).get("CompliantSummary", {}).get("SeveritySummary", {}).get("MediumCount", 0)
    )

    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type_noncompliant,
        ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
        Items=[{"Id": "item-1", "Severity": "CRITICAL", "Status": "NON_COMPLIANT"}],
    )
    ctx.on_cleanup(
        lambda: ssm.put_compliance_items(
            ResourceId=resource_id,
            ResourceType="ManagedInstance",
            ComplianceType=compliance_type_noncompliant,
            ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
            Items=[],
        )
    )
    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type_compliant,
        ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
        Items=[{"Id": "item-2", "Severity": "MEDIUM", "Status": "COMPLIANT"}],
    )
    ctx.on_cleanup(
        lambda: ssm.put_compliance_items(
            ResourceId=resource_id,
            ResourceType="ManagedInstance",
            ComplianceType=compliance_type_compliant,
            ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
            Items=[],
        )
    )

    noncompliant_summary = _poll_until(
        lambda: _summary(compliance_type_noncompliant),
        lambda s: s is not None
        and s.get("NonCompliantSummary", {}).get("NonCompliantCount", 0) >= base_noncompliant + 1,
        timeout_s=60.0,
        interval_s=3.0,
    )
    compliant_summary = _poll_until(
        lambda: _summary(compliance_type_compliant),
        lambda s: s is not None
        and s.get("CompliantSummary", {}).get("CompliantCount", 0) >= base_compliant + 1,
        timeout_s=60.0,
        interval_s=3.0,
    )

    nc_noncompliant = noncompliant_summary["NonCompliantSummary"]
    c_compliant = compliant_summary["CompliantSummary"]
    assert nc_noncompliant["NonCompliantCount"] == base_noncompliant + 1, noncompliant_summary
    assert nc_noncompliant["SeveritySummary"]["CriticalCount"] == base_critical + 1, noncompliant_summary
    assert c_compliant["CompliantCount"] == base_compliant + 1, compliant_summary
    assert c_compliant["SeveritySummary"]["MediumCount"] == base_medium + 1, compliant_summary


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _wait_for_agent_online(
    ctx, instance_id: str, timeout_s: float = 600.0, interval_s: float = 15.0
) -> None:
    ssm = ctx.client("ssm")
    if ctx.time_left() is not None:
        timeout_s = max(1.0, min(timeout_s, ctx.time_left() - 60.0))
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
        f"instance {instance_id} never reached PingStatus=Online within {timeout_s:.0f}s"
        " (SSM Agent never registered)"
    )


def _launch_ssm_managed_instance(ctx, extra_tags=None) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    )

    profile_name = ctx.unique_name("sim2real-ssmprof-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
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

    # IAM role/instance-profile propagation lag before EC2 will accept the profile: bounded
    # retry on InvalidParameterValue rather than a fixed pre-sleep.
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
