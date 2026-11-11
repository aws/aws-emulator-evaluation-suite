"""deploy-autoscaling-3-cdk-l2-asg-target-tracking-deploys-runs-and-drifts."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-autoscaling-3-cdk-l2-asg-target-tracking-deploys-runs-and-drifts"
GROUP = "deploy-cdk-asg-l2"
SERVICES = ["autoscaling", "cloudformation", "cloudwatch", "ec2"]

# Budgets. Every wait below polls an observable condition; these are ceilings, not sleeps.
_SYNTH_TIMEOUT_S = 240.0
_CREATE_TIMEOUT_S = 720.0
_INSTANCE_RUNNING_TIMEOUT_S = 300.0
_DRIFT_TIMEOUT_S = 300.0
_DELETE_TIMEOUT_S = 720.0

_INSTANCE_TYPE = "t3.micro"
_TARGET_CPU = 50
_MIN, _MAX, _OUT_OF_BAND_MAX = 1, 2, 3

_CDK_APP_SOURCE = '''
import json
import os

from aws_cdk import App, CfnOutput, Environment, Stack, Tags
from aws_cdk import aws_autoscaling as autoscaling
from aws_cdk import aws_ec2 as ec2


class AsgStack(Stack):
    def __init__(self, scope, cid, **kw):
        super().__init__(scope, cid, **kw)
        # Its own VPC: public subnets only and NO NAT gateway, in the AZs the check derived from
        # the instance-type offerings, so nothing depends on an ambient default VPC.
        vpc = ec2.Vpc(
            self, "Vpc", nat_gateways=0,
            availability_zones=json.loads(os.environ["SIM2REAL_AZS"]),
            subnet_configuration=[ec2.SubnetConfiguration(
                name="public", subnet_type=ec2.SubnetType.PUBLIC, cidr_mask=24)],
        )
        sg = ec2.SecurityGroup(self, "Sg", vpc=vpc, allow_all_outbound=True)
        lt = ec2.LaunchTemplate(
            self, "Lt",
            instance_type=ec2.InstanceType(os.environ["SIM2REAL_INSTANCE_TYPE"]),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(),
            security_group=sg,
        )
        asg = autoscaling.AutoScalingGroup(
            self, "Asg", vpc=vpc, launch_template=lt,
            min_capacity=int(os.environ["SIM2REAL_MIN"]),
            max_capacity=int(os.environ["SIM2REAL_MAX"]),
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            update_policy=autoscaling.UpdatePolicy.rolling_update(
                max_batch_size=1, min_instances_in_service=0),
        )
        asg.scale_on_cpu_utilization(
            "Cpu", target_utilization_percent=int(os.environ["SIM2REAL_TARGET_CPU"]))
        Tags.of(self).add("sim2real", os.environ["SIM2REAL_CHECK_ID"])
        CfnOutput(self, "AsgName", value=asg.auto_scaling_group_name)
        CfnOutput(self, "VpcId", value=vpc.vpc_id)
        CfnOutput(self, "LaunchTemplateId", value=lt.launch_template_id)


app = App()
AsgStack(app, os.environ["SIM2REAL_STACK_NAME"], env=Environment(
    account=os.environ["CDK_DEFAULT_ACCOUNT"], region=os.environ["CDK_DEFAULT_REGION"]))
app.synth()
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:metrics",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CDK L2 ASG with scaleOnCpuUtilization(50) deploys via CloudFormation, runs EC2 capacity,
    gets target-tracking alarms in CloudWatch, drifts MODIFIED on /MaxSize after an out-of-band
    change, and leaves no instances or alarms once the stack is deleted.
    """
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    cfn = ctx.client("cloudformation")
    asg_client = ctx.client("autoscaling")
    cw = ctx.client("cloudwatch")
    ec2 = ctx.client("ec2")

    # ---- 0. AZs that can actually run the instance type (two, for the L2 VPC) ----------------
    offered = {o["Location"] for page in ec2.get_paginator(
        "describe_instance_type_offerings").paginate(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])
        for o in page["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= 2, (
        f"need two available AZs offering {_INSTANCE_TYPE!r}; usable={usable!r}, "
        f"offered={sorted(offered)!r}")
    azs = usable[:2]

    stack = ctx.unique_name("sim2real-xsvc-cdkasg-")

    # ---- 1. synth, and assert on the SYNTHESIZED template before anything is created --------
    template = _synth(ctx, acct, stack, azs)
    resources = template["Resources"]
    by_type: dict[str, list[str]] = {}
    for logical, res in resources.items():
        by_type.setdefault(res["Type"], []).append(logical)
    asg_ids = by_type.get("AWS::AutoScaling::AutoScalingGroup", [])
    assert len(asg_ids) == 1, (
        f"synthesized template has {len(asg_ids)} AutoScalingGroups, expected 1; types: "
        f"{sorted(by_type)!r}")
    asg_logical = asg_ids[0]
    assert "AWS::EC2::LaunchTemplate" in by_type and \
        "AWS::AutoScaling::LaunchConfiguration" not in by_type, (
            f"the L2 ASG was given a launch template, so the template must carry an "
            f"AWS::EC2::LaunchTemplate and no LaunchConfiguration; types: {sorted(by_type)!r}")
    rolling = resources[asg_logical].get("UpdatePolicy", {}).get("AutoScalingRollingUpdate")
    assert rolling and rolling.get("MaxBatchSize") == 1, (
        f"the ASG's UpdatePolicy is {resources[asg_logical].get('UpdatePolicy')!r}; "
        f"UpdatePolicy.rolling_update(max_batch_size=1) must synthesize an "
        f"AutoScalingRollingUpdate with MaxBatchSize 1")
    pol_ids = by_type.get("AWS::AutoScaling::ScalingPolicy", [])
    assert len(pol_ids) == 1, (
        f"synthesized template has {len(pol_ids)} ScalingPolicy resources, expected 1")
    pol_props = resources[pol_ids[0]]["Properties"]
    tt = pol_props.get("TargetTrackingConfiguration", {})
    assert pol_props.get("PolicyType") == "TargetTrackingScaling" and \
        tt.get("TargetValue") == _TARGET_CPU and \
        tt.get("PredefinedMetricSpecification", {}).get("PredefinedMetricType") == \
        "ASGAverageCPUUtilization", (
            f"scaleOnCpuUtilization({_TARGET_CPU}) synthesized {pol_props!r}; expected a "
            f"TargetTrackingScaling policy on ASGAverageCPUUtilization at {_TARGET_CPU}")
    assert "AWS::CloudWatch::Alarm" not in by_type, (
        f"the template declares CloudWatch alarms {by_type['AWS::CloudWatch::Alarm']!r}; the "
        f"alarm assertions below are only meaningful if Auto Scaling creates them itself")

    # ---- 2. deploy through plain CloudFormation ----------------------------------------------
    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        OnFailure="DELETE")["StackId"]
    # The net only ISSUES the delete (fits the 60s cleanup cap); CloudFormation finishes it.
    ctx.on_cleanup(lambda: _issue_delete(ctx, stack_id))
    state = _wait_stack(cfn, stack_id, {"CREATE_COMPLETE"},
                        {"CREATE_FAILED", "ROLLBACK_IN_PROGRESS", "ROLLBACK_COMPLETE",
                         "DELETE_IN_PROGRESS", "DELETE_COMPLETE"},
                        _CREATE_TIMEOUT_S)
    assert state == "CREATE_COMPLETE", (
        f"stack {stack!r} reached {state!r}, not CREATE_COMPLETE; failure events: "
        f"{_failure_events(cfn, stack_id)!r}")
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])}
    asg_name, vpc_id, lt_id = outputs["AsgName"], outputs["VpcId"], outputs["LaunchTemplateId"]
    torn_down = False
    instance_ids: list[str] = []
    try:
        # ---- 3. the ASG is what the construct declared --------------------------------------
        groups = asg_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        assert len(groups) == 1, f"DescribeAutoScalingGroups({asg_name!r}) -> {len(groups)} groups"
        group = groups[0]
        assert (group["MinSize"], group["MaxSize"]) == (_MIN, _MAX), (
            f"ASG {asg_name!r} has MinSize/MaxSize {(group['MinSize'], group['MaxSize'])!r}, "
            f"expected {(_MIN, _MAX)!r}")
        assert group.get("LaunchTemplate", {}).get("LaunchTemplateId") == lt_id, (
            f"ASG {asg_name!r} launch template is {group.get('LaunchTemplate')!r}, expected the "
            f"stack's {lt_id!r}")

        # ---- 4. the target-tracking policy, read back from Auto Scaling ----------------------
        policies = asg_client.describe_policies(AutoScalingGroupName=asg_name)["ScalingPolicies"]
        assert len(policies) == 1, (
            f"ASG {asg_name!r} has {len(policies)} scaling policies "
            f"({[p['PolicyName'] for p in policies]!r}), expected the one CDK declared")
        policy = policies[0]
        assert policy["PolicyType"] == "TargetTrackingScaling", (
            f"policy {policy['PolicyName']!r} has PolicyType {policy['PolicyType']!r}, "
            f"expected 'TargetTrackingScaling'")
        cfg = policy["TargetTrackingConfiguration"]
        assert cfg["TargetValue"] == float(_TARGET_CPU), (
            f"policy TargetValue is {cfg['TargetValue']!r}, expected {float(_TARGET_CPU)!r}")
        assert cfg["PredefinedMetricSpecification"]["PredefinedMetricType"] == \
            "ASGAverageCPUUtilization", f"policy tracks {cfg!r}, expected ASGAverageCPUUtilization"
        alarm_names = sorted(a["AlarmName"] for a in policy.get("Alarms", []))
        assert len(alarm_names) == 2, (
            f"a target-tracking policy (scale-in enabled) must carry two Auto Scaling-created "
            f"alarms; DescribePolicies lists {alarm_names!r}")

        # ---- 5. CloudWatch really holds those alarms, wired back to the policy ---------------
        alarms = cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]
        assert sorted(a["AlarmName"] for a in alarms) == alarm_names, (
            f"DescribeAlarms({alarm_names!r}) returned {[a['AlarmName'] for a in alarms]!r}")
        for a in alarms:
            dims = {d["Name"]: d["Value"] for d in a.get("Dimensions", [])}
            assert (a["Namespace"], a["MetricName"], dims) == (
                "AWS/EC2", "CPUUtilization", {"AutoScalingGroupName": asg_name}), (
                f"alarm {a['AlarmName']!r} watches {a['Namespace']!r}/{a['MetricName']!r} "
                f"{dims!r}, expected AWS/EC2/CPUUtilization for AutoScalingGroupName={asg_name!r}")
            assert policy["PolicyARN"] in a.get("AlarmActions", []), (
                f"alarm {a['AlarmName']!r} actions {a.get('AlarmActions')!r} do not invoke the "
                f"policy {policy['PolicyARN']!r}")
        high = [a for a in alarms if a["ComparisonOperator"] == "GreaterThanThreshold"]
        low = [a for a in alarms if a["ComparisonOperator"] == "LessThanThreshold"]
        assert len(high) == 1 and len(low) == 1, (
            f"expected one scale-out (GreaterThanThreshold) and one scale-in "
            f"(LessThanThreshold) alarm; got "
            f"{[(a['AlarmName'], a['ComparisonOperator']) for a in alarms]!r}")
        assert high[0]["Threshold"] == float(_TARGET_CPU), (
            f"scale-out alarm threshold is {high[0]['Threshold']!r}, expected the target "
            f"{float(_TARGET_CPU)!r}")
        assert low[0]["Threshold"] < float(_TARGET_CPU), (
            f"scale-in alarm threshold {low[0]['Threshold']!r} must sit below the target "
            f"{float(_TARGET_CPU)!r}")

        # ---- 6. capacity is real: instances running at EC2, launched from the stack's LT -----
        instance_ids = _wait_running_instances(asg_client, ec2, asg_name)
        assert _MIN <= len(instance_ids) <= _MAX, (
            f"ASG {asg_name!r} runs {len(instance_ids)} instances {instance_ids!r}, outside "
            f"[{_MIN}, {_MAX}]")
        subnets = {s["SubnetId"] for s in ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]}
        for inst in _describe_instances(ec2, instance_ids):
            itags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            assert inst["State"]["Name"] == "running", (
                f"instance {inst['InstanceId']!r} is {inst['State']['Name']!r} at EC2")
            assert inst["InstanceType"] == _INSTANCE_TYPE, (
                f"instance {inst['InstanceId']!r} is {inst['InstanceType']!r}, the launch template "
                f"says {_INSTANCE_TYPE!r}")
            assert inst["SubnetId"] in subnets, (
                f"instance {inst['InstanceId']!r} is in subnet {inst['SubnetId']!r}, not one of the "
                f"stack VPC's {sorted(subnets)!r}")
            assert itags.get("aws:autoscaling:groupName") == asg_name, (
                f"instance {inst['InstanceId']!r} carries aws:autoscaling:groupName "
                f"{itags.get('aws:autoscaling:groupName')!r}, expected {asg_name!r}")
            assert itags.get("aws:ec2launchtemplate:id") == lt_id, (
                f"instance {inst['InstanceId']!r} carries aws:ec2launchtemplate:id "
                f"{itags.get('aws:ec2launchtemplate:id')!r}, expected the stack's {lt_id!r}")
            assert itags.get("sim2real") == CHECK, (
                f"instance {inst['InstanceId']!r} tag sim2real={itags.get('sim2real')!r}: the stack "
                f"tag must propagate at launch (PropagateAtLaunch)")

        # ---- 7. drift: IN_SYNC baseline, then out-of-band MaxSize -> MODIFIED on /MaxSize ----
        base = _detect_drift(cfn, stack_id)
        assert base["StackDriftStatus"] == "IN_SYNC", (
            f"freshly deployed stack {stack!r} reports drift {base['StackDriftStatus']!r} before "
            f"any out-of-band change; the post-change MODIFIED below would prove nothing")
        asg_client.update_auto_scaling_group(
            AutoScalingGroupName=asg_name, MaxSize=_OUT_OF_BAND_MAX)
        live_max = asg_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]["MaxSize"]
        assert live_max == _OUT_OF_BAND_MAX, (
            f"UpdateAutoScalingGroup(MaxSize={_OUT_OF_BAND_MAX}) left MaxSize at {live_max!r}")
        after = _detect_drift(cfn, stack_id)
        assert after["StackDriftStatus"] == "DRIFTED", (
            f"after an out-of-band MaxSize change the stack reports "
            f"{after['StackDriftStatus']!r}, expected 'DRIFTED'")
        drifts = _describe_stack_resource_drifts(cfn, stack_id, ["MODIFIED"])
        assert [d["LogicalResourceId"] for d in drifts] == [asg_logical], (
            f"MODIFIED resources are {[d['LogicalResourceId'] for d in drifts]!r}; exactly the "
            f"ASG {asg_logical!r} was changed out of band")
        diffs = {p["PropertyPath"]: p for p in drifts[0]["PropertyDifferences"]}
        assert sorted(diffs) == ["/MaxSize"], (
            f"ASG drift property paths are {sorted(diffs)!r}, expected exactly ['/MaxSize']")
        mx = diffs["/MaxSize"]
        assert (mx["ExpectedValue"], mx["ActualValue"], mx["DifferenceType"]) == (
            str(_MAX), str(_OUT_OF_BAND_MAX), "NOT_EQUAL"), (
            f"/MaxSize drift is {mx!r}; expected ExpectedValue {str(_MAX)!r}, ActualValue "
            f"{str(_OUT_OF_BAND_MAX)!r}, DifferenceType 'NOT_EQUAL'")

        # ---- 8. teardown, asserted at EC2 / Auto Scaling / CloudWatch -------------------------
        cfn.delete_stack(StackName=stack_id)
        torn_down = True
        end = _wait_stack(cfn, stack_id, {"DELETE_COMPLETE"}, {"DELETE_FAILED"}, _DELETE_TIMEOUT_S)
        assert end == "DELETE_COMPLETE", (
            f"stack {stack!r} reached {end!r} on delete; failure events: "
            f"{_failure_events(cfn, stack_id)!r}")
        left = {i["InstanceId"]: i["State"]["Name"] for i in _describe_instances(ec2, instance_ids)
                if i["State"]["Name"] != "terminated"}
        assert not left, f"after DELETE_COMPLETE these ASG instances are not terminated: {left!r}"
        gone = asg_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        assert gone == [], f"ASG {asg_name!r} still listed after stack delete: {gone!r}"
        stale = [a["AlarmName"] for a in cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]]
        assert stale == [], f"target-tracking alarms survived their policy's deletion: {stale!r}"
        code, message = _error(lambda: ec2.describe_launch_templates(LaunchTemplateIds=[lt_id]))
        assert code == "InvalidLaunchTemplateId.NotFound", (
            f"DescribeLaunchTemplates({lt_id!r}) after delete raised {code!r}, expected "
            f"'InvalidLaunchTemplateId.NotFound'")
        expected = "At least one of the launch templates specified in the request does not exist."
        assert message == expected, f"DescribeLaunchTemplates message {message!r}, expected {expected!r}"
        code, message = _error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]))
        assert code == "InvalidVpcID.NotFound", (
            f"DescribeVpcs({vpc_id!r}) after delete raised {code!r}, expected "
            f"'InvalidVpcID.NotFound'")
        expected = f"The vpc ID '{vpc_id}' does not exist"
        assert message == expected, f"DescribeVpcs message {message!r}, expected {expected!r}"
    finally:
        if not torn_down:
            # The check failed before its own teardown: delete and wait inside the check's budget
            # (the cleanup net alone cannot wait past 60s). Report, never mask the verdict.
            try:
                cfn.delete_stack(StackName=stack_id)
                end = _wait_stack(cfn, stack_id, {"DELETE_COMPLETE"}, {"DELETE_FAILED"},
                                  _DELETE_TIMEOUT_S)
                if end != "DELETE_COMPLETE":
                    print(f"stack {stack_id} ended {end!r}; instances {instance_ids!r}")
            except Exception as exc:  # noqa: BLE001 - teardown reports, never masks the verdict
                print(f"stack {stack_id} teardown failed: {exc!r}")


def _error(fn) -> tuple:
    """The AWS error (code, message) a call raises. Raises when the call SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), exc.response["Error"].get("Message")
    raise AssertionError("call succeeded but was expected to be refused")


def _synth(ctx, acct: str, stack: str, azs: list[str]) -> dict[str, Any]:
    """`cdk synth` the inline app in a temp dir; return the template with CDK's bootstrap-version
    parameter/rule pair stripped so CreateStack needs no bootstrapped environment."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-xsvc-cdkasg-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    (work / "app.py").write_text(_CDK_APP_SOURCE)
    (work / "cdk.json").write_text(json.dumps({"app": f"{sys.executable} app.py"}))
    env = ctx.subprocess_env()
    env.update({
        "CDK_DEFAULT_ACCOUNT": acct, "CDK_DEFAULT_REGION": ctx.region,
        "SIM2REAL_STACK_NAME": stack, "SIM2REAL_CHECK_ID": CHECK,
        "SIM2REAL_AZS": json.dumps(azs), "SIM2REAL_INSTANCE_TYPE": _INSTANCE_TYPE,
        "SIM2REAL_MIN": str(_MIN), "SIM2REAL_MAX": str(_MAX),
        "SIM2REAL_TARGET_CPU": str(_TARGET_CPU),
        "JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION": "1",
    })
    r = subprocess.run(
        ["cdk", "synth", "--ci", "--no-version-reporting", "--no-asset-metadata",
         "--no-path-metadata", "--output", str(work / "cdk.out")],
        cwd=work, env=env, capture_output=True, text=True, timeout=_SYNTH_TIMEOUT_S)
    assert r.returncode == 0, f"cdk synth rc={r.returncode}: {(r.stdout + r.stderr)[-1200:]!r}"
    path = work / "cdk.out" / f"{stack}.template.json"
    assert path.is_file(), (
        f"cdk synth wrote no {path.name}; cdk.out has "
        f"{sorted(p.name for p in (work / 'cdk.out').iterdir())!r}")
    doc = json.loads(path.read_text())
    (doc.get("Parameters") or {}).pop("BootstrapVersion", None)
    (doc.get("Rules") or {}).pop("CheckBootstrapVersion", None)
    for key in ("Parameters", "Rules"):
        if key in doc and not doc[key]:
            doc.pop(key)
    rest = json.dumps(doc)
    assert "/cdk-bootstrap/" not in rest and "cdk-hnb659fds" not in rest, (
        "the synthesized template still references CDK bootstrap resources; the app must stay "
        "asset-free to deploy through plain CloudFormation")
    return doc


def _describe_stack_resource_drifts(
        cfn, stack_id: str, statuses: list[str]) -> list[dict[str, Any]]:
    """``DescribeStackResourceDrifts`` paginated by hand: botocore ships no paginator config for
    this operation (``can_paginate`` is False), unlike most other ``Describe*`` calls here."""
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {
            "StackName": stack_id, "StackResourceDriftStatusFilters": statuses}
        if token:
            kwargs["NextToken"] = token
        resp = cfn.describe_stack_resource_drifts(**kwargs)
        out.extend(resp["StackResourceDrifts"])
        token = resp.get("NextToken")
        if not token:
            return out


def _issue_delete(ctx, stack_id: str) -> None:
    try:
        ctx.client("cloudformation").delete_stack(StackName=stack_id)
    except ClientError as exc:
        raise RuntimeError(f"delete_stack({stack_id}) refused: {exc!r}") from exc


def _wait_stack(cfn, stack_id: str, done: set[str], bad: set[str], timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in done or status in bad:
            return status
        time.sleep(2)
    return f"TIMEOUT after {timeout_s}s in {status}"


def _failure_events(cfn, stack_id: str) -> list[tuple[str, str, str]]:
    try:
        events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    except ClientError as exc:
        return [("describe_stack_events", "error", repr(exc))]
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason", ""))
            for e in events if "FAILED" in e["ResourceStatus"]][:8]


def _describe_instances(ec2, ids: list[str]) -> list[dict[str, Any]]:
    if not ids:
        return []
    out: list[dict[str, Any]] = []
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=ids):
        for res in page["Reservations"]:
            out.extend(res["Instances"])
    return out


def _wait_running_instances(asg_client, ec2, asg_name: str) -> list[str]:
    """Poll until the ASG has >= 1 InService instance and EC2 reports every one of them
    running. Raises on timeout with the last observation."""
    deadline = time.monotonic() + _INSTANCE_RUNNING_TIMEOUT_S
    seen: Any = None
    while time.monotonic() < deadline:
        group = asg_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0]
        ids = sorted(i["InstanceId"] for i in group["Instances"]
                     if i["LifecycleState"] == "InService")
        states = {i["InstanceId"]: i["State"]["Name"] for i in _describe_instances(ec2, ids)}
        seen = (group["Instances"], states)
        if ids and all(states.get(i) == "running" for i in ids):
            return ids
        time.sleep(2)
    raise AssertionError(
        f"ASG {asg_name!r} never had a running InService instance within "
        f"{_INSTANCE_RUNNING_TIMEOUT_S}s; last (asg instances, ec2 states) = {seen!r}")


def _detect_drift(cfn, stack_id: str) -> dict[str, Any]:
    det = cfn.detect_stack_drift(StackName=stack_id)["StackDriftDetectionId"]
    deadline = time.monotonic() + _DRIFT_TIMEOUT_S
    status: dict[str, Any] = {}
    while time.monotonic() < deadline:
        status = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=det)
        if status["DetectionStatus"] != "DETECTION_IN_PROGRESS":
            assert status["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"drift detection {det!r} ended {status['DetectionStatus']!r}: "
                f"{status.get('DetectionStatusReason')!r}")
            return status
        time.sleep(5.0)
    raise AssertionError(f"drift detection {det!r} still in progress after {_DRIFT_TIMEOUT_S}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
