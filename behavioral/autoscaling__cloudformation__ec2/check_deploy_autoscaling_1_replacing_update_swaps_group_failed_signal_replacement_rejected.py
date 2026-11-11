"""deploy-autoscaling-1-replacing-update-swaps-group-failed-signal-replacement-rejected."""
from __future__ import annotations

import base64
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-autoscaling-1-replacing-update-swaps-group-failed-signal-replacement-rejected"
GROUP = "deploy-asg-update-paths"
SERVICES = ["autoscaling", "cloudformation", "ec2"]

DESIRED = 2
INSTANCE_TYPE = "t3.micro"
LOGICAL_ASG = "AutoScalingGroup"

# The template is inlined so the check is one self-contained file. It is the replacing-update
# twin of deployments/asg-rolling-update-signals.yaml: same signal path (instances call
# `aws cloudformation signal-resource` from UserData under an instance profile scoped to this
# stack), but the group carries `UpdatePolicy: AutoScalingReplacingUpdate: WillReplace: true`
# and NO AutoScalingGroupName, because CloudFormation cannot replace a custom-named resource.
TEMPLATE = r"""
AWSTemplateFormatVersion: '2010-09-09'
Description: >-
  sim2real-xsvc Auto Scaling group with AutoScalingReplacingUpdate (WillReplace) and a
  CreationPolicy ResourceSignal. Bumping Generation rewrites the launch template UserData,
  which changes the group's LaunchTemplate property and makes CloudFormation build a whole
  new group; SignalExitCode=1 makes that new group's instances signal FAILURE.
Parameters:
  ImageId:
    Type: String
  AvailabilityZone:
    Type: String
  LaunchTemplateName:
    Type: String
  Generation:
    Type: String
    Default: '1'
  SignalExitCode:
    Type: String
    Default: '0'
    AllowedValues: ['0', '1']
  DesiredCapacity:
    Type: String
    Default: '2'
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.173.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: Name
          Value: !Sub 'sim2real-xsvc-rp-vpc-${AWS::StackName}'
        - Key: 'sim2real:managed'
          Value: 'true'
  InternetGateway:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags:
        - Key: 'sim2real:managed'
          Value: 'true'
  AttachGateway:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref Vpc
      InternetGatewayId: !Ref InternetGateway
  RouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref Vpc
  DefaultRoute:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref RouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref InternetGateway
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.173.1.0/24
      AvailabilityZone: !Ref AvailabilityZone
      MapPublicIpOnLaunch: true
      Tags:
        - Key: 'sim2real:managed'
          Value: 'true'
  SubnetARouteAssoc:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref SubnetA
      RouteTableId: !Ref RouteTable
  SignalRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: signal-this-stack-only
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: cloudformation:SignalResource
                Resource: !Ref AWS::StackId
      Tags:
        - Key: 'sim2real:managed'
          Value: 'true'
  SignalInstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref SignalRole
  LaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: !Ref LaunchTemplateName
      LaunchTemplateData:
        ImageId: !Ref ImageId
        InstanceType: t3.micro
        IamInstanceProfile:
          Arn: !GetAtt SignalInstanceProfile.Arn
        TagSpecifications:
          - ResourceType: instance
            Tags:
              - Key: 'sim2real:managed'
                Value: 'true'
              - Key: 'sim2real:prefix'
                Value: sim2real-xsvc
          - ResourceType: volume
            Tags:
              - Key: 'sim2real:managed'
                Value: 'true'
              - Key: 'sim2real:prefix'
                Value: sim2real-xsvc
        UserData:
          Fn::Base64: !Sub |
            #!/bin/bash
            # generation=${Generation} signal=${SignalExitCode}
            set -u
            TOKEN=$(curl -sS -m 10 -X PUT "http://169.254.169.254/latest/api/token" \
              -H "X-aws-ec2-metadata-token-ttl-seconds: 300" || echo "")
            IID=$(curl -sS -m 10 -H "X-aws-ec2-metadata-token: ${!TOKEN}" \
              http://169.254.169.254/latest/meta-data/instance-id || echo "")
            if [ "${SignalExitCode}" = "0" ]; then
              STATUS=SUCCESS
            else
              STATUS=FAILURE
            fi
            for _ in $(seq 1 30); do
              if aws cloudformation signal-resource \
                   --region ${AWS::Region} \
                   --stack-name ${AWS::StackName} \
                   --logical-resource-id AutoScalingGroup \
                   --unique-id "${!IID}" \
                   --status "${!STATUS}"; then
                exit 0
              fi
              sleep 10
            done
            exit 1
  AutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    DependsOn: DefaultRoute
    Properties:
      MinSize: '1'
      MaxSize: !Ref DesiredCapacity
      DesiredCapacity: !Ref DesiredCapacity
      HealthCheckType: EC2
      HealthCheckGracePeriod: 0
      VPCZoneIdentifier:
        - !Ref SubnetA
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplate
        Version: !GetAtt LaunchTemplate.LatestVersionNumber
      Tags:
        - Key: 'sim2real:managed'
          Value: 'true'
          PropagateAtLaunch: true
        - Key: 'sim2real:prefix'
          Value: sim2real-xsvc
          PropagateAtLaunch: true
    CreationPolicy:
      AutoScalingCreationPolicy:
        MinSuccessfulInstancesPercent: 100
      ResourceSignal:
        Count: !Ref DesiredCapacity
        Timeout: PT12M
    UpdatePolicy:
      AutoScalingReplacingUpdate:
        WillReplace: true
Outputs:
  AsgNameOut:
    Value: !Ref AutoScalingGroup
  LaunchTemplateId:
    Value: !Ref LaunchTemplate
"""

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}


@tags(
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
    "axis:rejection",
)
def run(ctx) -> None:
    """An AutoScalingReplacingUpdate builds a NEW group, swaps it in and deletes the old one with
    its instances; when the new group's instances signal FAILURE the replacement is rejected, the
    stack rolls back and the ORIGINAL group survives untouched.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    ctx.verify_account_safety()

    # ---- Every decidable precondition before any create. ----
    image_id = _latest_amazon_linux_ami(ec2)
    az = _usable_az(ec2, INSTANCE_TYPE)

    stack_a = ctx.unique_name("sim2real-xsvc-rpa-")
    stack_b = ctx.unique_name("sim2real-xsvc-rpb-")
    base = {"ImageId": image_id, "AvailabilityZone": az, "DesiredCapacity": str(DESIRED),
            "Generation": "1", "SignalExitCode": "0"}
    params = {
        stack_a: {**base, "LaunchTemplateName": ctx.unique_name("sim2real-xsvc-rpa-lt-")},
        stack_b: {**base, "LaunchTemplateName": ctx.unique_name("sim2real-xsvc-rpb-lt-")},
    }

    # Registered BEFORE the creates: one net that issues every delete first and then waits, so
    # teardown costs the max of the two stacks rather than the sum. delete_stack on a name that
    # was never created is a no-op, so registering early is safe.
    ctx.on_cleanup(lambda: _delete_stacks_and_wait(cfn, [stack_a, stack_b], timeout_s=1500.0,
                                                   raise_on_leak=True))

    # ---- 1. Create both stacks; CREATE_COMPLETE needs DESIRED SUCCESS signals each. ----
    for name in (stack_a, stack_b):
        cfn.create_stack(
            StackName=name,
            TemplateBody=TEMPLATE,
            Parameters=_cfn_params(params[name]),
            Capabilities=["CAPABILITY_IAM"],
            Tags=[{"Key": "sim2real:managed", "Value": "true"},
                  {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"}],
        )
    created = _wait_all(cfn, [stack_a, stack_b], _CREATE_TERMINAL, timeout_s=1500.0,
                        description="stack create")
    for name, status in created.items():
        assert status == "CREATE_COMPLETE", (
            f"stack {name} must reach CREATE_COMPLETE once {DESIRED} instances signal SUCCESS, "
            f"got {status!r}: {_failure_reasons(cfn, name)[:4]!r}"
        )

    asg_a1 = _physical_asg(cfn, stack_a)
    asg_b1 = _physical_asg(cfn, stack_b)
    assert asg_a1 == _outputs(cfn, stack_a)["AsgNameOut"], (
        f"stack A's AsgNameOut {_outputs(cfn, stack_a).get('AsgNameOut')!r} disagrees with its "
        f"PhysicalResourceId {asg_a1!r}"
    )
    a1_ids = _in_service_ids(autoscaling, asg_a1)
    b1_ids = _in_service_ids(autoscaling, asg_b1)
    for label, group, ids in (("A", asg_a1, a1_ids), ("B", asg_b1, b1_ids)):
        assert len(ids) == DESIRED, (
            f"stack {label}'s group {group} must hold {DESIRED} InService instances after "
            f"CREATE_COMPLETE, got {ids!r}"
        )
        # Read the instances at EC2, not just at Auto Scaling: they are real, running, and booted
        # the generation-1 UserData.
        for iid in ids:
            state = _ec2_state(ec2, iid)
            assert state == "running", f"group {group} instance {iid} is {state!r} at EC2"
            ud = _instance_user_data(ec2, iid)
            assert "generation=1 signal=0" in ud, (
                f"instance {iid} of {group} must carry the generation-1 UserData, got {ud[:160]!r}"
            )

    # ---- 2. Update both: same generation bump; B alone signals FAILURE. ----
    cfn.update_stack(StackName=stack_a, TemplateBody=TEMPLATE, Capabilities=["CAPABILITY_IAM"],
                     Parameters=_cfn_params({**params[stack_a], "Generation": "2"}))
    cfn.update_stack(StackName=stack_b, TemplateBody=TEMPLATE, Capabilities=["CAPABILITY_IAM"],
                     Parameters=_cfn_params({**params[stack_b], "Generation": "2",
                                             "SignalExitCode": "1"}))
    updated = _wait_all(cfn, [stack_a, stack_b], _UPDATE_TERMINAL, timeout_s=1800.0,
                        description="stack update")

    # ---- 3. A: the group was REPLACED, and the old one is gone from Auto Scaling. ----
    assert updated[stack_a] == "UPDATE_COMPLETE", (
        f"stack A's replacing update must succeed when every new instance signals SUCCESS, got "
        f"{updated[stack_a]!r}: {_failure_reasons(cfn, stack_a)[:4]!r}"
    )
    asg_a2 = _physical_asg(cfn, stack_a)
    assert asg_a2 != asg_a1, (
        f"WillReplace=true must give the group a NEW PhysicalResourceId, but it is still {asg_a1!r}"
    )
    assert _outputs(cfn, stack_a)["AsgNameOut"] == asg_a2, (
        f"stack A's AsgNameOut must follow the replacement to {asg_a2!r}, got "
        f"{_outputs(cfn, stack_a).get('AsgNameOut')!r}"
    )
    gone = _poll_until(
        lambda: _group_names_present(autoscaling, [asg_a1]),
        lambda present: present == [],
        timeout_s=600.0, interval_s=10.0,
        description=f"old group {asg_a1} absent from DescribeAutoScalingGroups",
    )
    assert gone == [], f"old group {asg_a1} is still listed: {gone!r}"

    # ---- 4. A: new instances run the new UserData; old instances are terminated at EC2. ----
    a2_ids = _in_service_ids(autoscaling, asg_a2)
    assert len(a2_ids) == DESIRED, (
        f"replacement group {asg_a2} must hold {DESIRED} InService instances, got {a2_ids!r}"
    )
    assert not set(a2_ids) & set(a1_ids), (
        f"a replacing update builds a new group with NEW instances, yet {sorted(set(a2_ids) & set(a1_ids))!r} "
        f"carried over from {asg_a1}"
    )
    for iid in a2_ids:
        state = _ec2_state(ec2, iid)
        assert state == "running", f"replacement instance {iid} is {state!r} at EC2"
        ud = _instance_user_data(ec2, iid)
        assert "generation=2 signal=0" in ud, (
            f"replacement instance {iid} must carry the generation-2 UserData, got {ud[:160]!r}"
        )
        assert "generation=1" not in ud, f"replacement instance {iid} carries the OLD UserData"
    old_states = _poll_until(
        lambda: {iid: _ec2_state(ec2, iid) for iid in a1_ids},
        lambda states: all(s == "terminated" for s in states.values()),
        timeout_s=600.0, interval_s=10.0,
        description=f"old group {asg_a1}'s instances terminated at EC2",
    )
    assert set(old_states.values()) == {"terminated"}, f"old instances: {old_states!r}"

    # ---- 5. B: the FAILURE-signalled replacement is rejected; the ORIGINAL group survives. ----
    assert updated[stack_b] == "UPDATE_ROLLBACK_COMPLETE", (
        f"a replacement whose instances signal FAILURE must be rejected and the stack rolled back, "
        f"but stack B ended in {updated[stack_b]!r}. UPDATE_COMPLETE means the FAILURE signal was "
        f"ignored. Reasons: {_failure_reasons(cfn, stack_b)[:4]!r}"
    )
    assert _physical_asg(cfn, stack_b) == asg_b1, (
        f"after the rollback the stack must point at the ORIGINAL group {asg_b1!r}, got "
        f"{_physical_asg(cfn, stack_b)!r}"
    )
    b_replacements = _replacement_groups(cfn, stack_b, original=asg_b1)
    assert len(b_replacements) == 1, (
        f"stack B's events must show exactly one replacement group attempted besides {asg_b1}, "
        f"got {b_replacements!r}"
    )
    asg_b2 = b_replacements[0]
    fail_reasons = [r for r in _asg_event_reasons(cfn, stack_b, asg_b2) if "FAILURE" in r]
    assert fail_reasons, (
        f"no stack event for the replacement group {asg_b2} names a FAILURE signal, so the "
        f"rollback is not attributable to the injected verdict: "
        f"{_asg_event_reasons(cfn, stack_b, asg_b2)[:6]!r}"
    )
    present = _poll_until(
        lambda: _group_names_present(autoscaling, [asg_b1, asg_b2]),
        lambda names: names == [asg_b1],
        timeout_s=600.0, interval_s=10.0,
        description=f"only the original group {asg_b1} remains (replacement {asg_b2} deleted)",
    )
    assert present == [asg_b1], f"groups present after rollback: {present!r}"
    b_after = _in_service_ids(autoscaling, asg_b1)
    assert b_after == b1_ids, (
        f"the original group must keep its original instances through a rejected replacement: "
        f"before={b1_ids!r}, after={b_after!r}"
    )
    for iid in b_after:
        state = _ec2_state(ec2, iid)
        assert state == "running", f"original instance {iid} is {state!r} after the rollback"
        assert "generation=1 signal=0" in _instance_user_data(ec2, iid), (
            f"original instance {iid} no longer carries generation-1 UserData"
        )
    b2_ids = _instances_of_group(ec2, asg_b2)
    assert b2_ids, (
        f"EC2 shows no instance ever launched for the replacement group {asg_b2}, so the FAILURE "
        f"signal cannot have come from it"
    )
    b2_states = _poll_until(
        lambda: {iid: _ec2_state(ec2, iid) for iid in b2_ids},
        lambda states: all(s == "terminated" for s in states.values()),
        timeout_s=600.0, interval_s=10.0,
        description=f"rejected replacement {asg_b2}'s instances terminated at EC2",
    )
    assert set(b2_states.values()) == {"terminated"}, f"rejected replacement instances: {b2_states!r}"

    # ---- Teardown, asserted at EC2 rather than at the stack status. ----
    deleted = _delete_stacks_and_wait(cfn, [stack_a, stack_b], timeout_s=1500.0)
    assert deleted == {stack_a: "DELETE_COMPLETE", stack_b: "DELETE_COMPLETE"}, (
        f"both stacks must delete cleanly: {deleted!r}"
    )
    leftover_groups = _group_names_present(autoscaling, [asg_a1, asg_a2, asg_b1, asg_b2])
    assert leftover_groups == [], f"groups still present after stack delete: {leftover_groups!r}"
    every_instance = sorted(set(a1_ids) | set(a2_ids) | set(b1_ids) | set(b2_ids))
    final = _poll_until(
        lambda: {iid: _ec2_state(ec2, iid) for iid in every_instance},
        lambda states: all(s == "terminated" for s in states.values()),
        timeout_s=600.0, interval_s=10.0,
        description="every instance the check saw is terminated at EC2 after stack delete",
    )
    assert set(final.values()) == {"terminated"}, f"instances after teardown: {final!r}"


def _cfn_params(values: dict[str, str]) -> list[dict[str, str]]:
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in values.items()]


def _latest_amazon_linux_ami(ec2) -> str:
    """The newest Amazon-owned Amazon Linux 2023 x86_64 AMI in this region (ships the aws CLI)."""
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2*-kernel-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "architecture", "Values": ["x86_64"]},
        ],
    )["Images"]
    assert images, "no Amazon Linux 2023 x86_64 AMI is available in this region"
    return max(images, key=lambda i: i.get("CreationDate", ""))["ImageId"]


def _usable_az(ec2, instance_type: str) -> str:
    """An available AZ that offers the instance type -- never a hardcoded or AWS-chosen one."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _stack_status(cfn, name: str) -> str:
    return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]


def _outputs(cfn, name: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _physical_asg(cfn, name: str) -> str:
    res = cfn.describe_stack_resource(StackName=name, LogicalResourceId=LOGICAL_ASG)
    return res["StackResourceDetail"]["PhysicalResourceId"]


def _stack_events(cfn, name: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        events.extend(page["StackEvents"])
    return events


def _failure_reasons(cfn, name: str) -> list[str]:
    return [
        f"{e.get('LogicalResourceId')}:{e.get('ResourceStatus')}:{e.get('ResourceStatusReason')}"
        for e in _stack_events(cfn, name)
        if "FAILED" in e.get("ResourceStatus", "") and e.get("ResourceStatusReason")
    ]


def _replacement_groups(cfn, name: str, *, original: str) -> list[str]:
    """Every group PhysicalResourceId the stack's events name other than the original one."""
    return sorted({
        e["PhysicalResourceId"]
        for e in _stack_events(cfn, name)
        if e.get("LogicalResourceId") == LOGICAL_ASG
        and e.get("PhysicalResourceId")
        and e["PhysicalResourceId"] != original
    })


def _asg_event_reasons(cfn, name: str, physical_id: str) -> list[str]:
    return [
        e["ResourceStatusReason"]
        for e in _stack_events(cfn, name)
        if e.get("LogicalResourceId") == LOGICAL_ASG
        and e.get("PhysicalResourceId") == physical_id
        and e.get("ResourceStatusReason")
    ]


def _in_service_ids(autoscaling, asg_name: str) -> list[str]:
    groups = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"]
    assert groups, f"auto scaling group {asg_name!r} not found"
    return sorted(
        i["InstanceId"] for i in groups[0]["Instances"] if i["LifecycleState"] == "InService"
    )


def _group_names_present(autoscaling, names: list[str]) -> list[str]:
    """Which of these exact group names DescribeAutoScalingGroups still returns (paginated)."""
    present: list[str] = []
    for page in autoscaling.get_paginator("describe_auto_scaling_groups").paginate(
        AutoScalingGroupNames=names
    ):
        present.extend(g["AutoScalingGroupName"] for g in page["AutoScalingGroups"])
    return sorted(present)


def _ec2_state(ec2, instance_id: str) -> str:
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst["State"]["Name"]
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


def _instances_of_group(ec2, asg_name: str) -> list[str]:
    """Every instance EC2 has ever recorded for a group, in any state, via its ASG tag."""
    ids: set[str] = set()
    for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "tag:aws:autoscaling:groupName", "Values": [asg_name]}]
    ):
        for reservation in page["Reservations"]:
            ids.update(i["InstanceId"] for i in reservation["Instances"])
    return sorted(ids)


def _instance_user_data(ec2, instance_id: str) -> str:
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="userData")
    encoded = (attr.get("UserData") or {}).get("Value")
    assert encoded, f"instance {instance_id} reports no UserData at EC2"
    return base64.b64decode(encoded).decode("utf-8", errors="replace")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_all(cfn, names: list[str], terminal: set[str], *, timeout_s: float,
              description: str) -> dict[str, str]:
    """Poll several stacks together until each is in a terminal status; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    statuses: dict[str, str] = {}
    while True:
        statuses = {n: _stack_status(cfn, n) for n in names}
        if all(s in terminal for s in statuses.values()):
            return statuses
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not terminal within {timeout_s}s: {statuses!r}")
        time.sleep(2)


def _delete_stacks_and_wait(cfn, names: list[str], *, timeout_s: float,
                            raise_on_leak: bool = False) -> dict[str, str]:
    """Issue every delete first, then wait for all and return the statuses.

    With ``raise_on_leak`` (the cleanup call) a stack left undeleted raises, so it lands in
    cleanup_detail; a failed delete_stack always raises.
    """
    for n in names:
        cfn.delete_stack(StackName=n)
    deadline = time.monotonic() + timeout_s
    statuses: dict[str, str] = {}
    while True:
        for n in names:
            try:
                statuses[n] = _stack_status(cfn, n)
            except ClientError as exc:
                # Gone by name: DescribeStacks on a deleted stack name is a ValidationError.
                err = exc.response.get("Error", {})
                if err.get("Code") != "ValidationError" or "does not exist" not in err.get("Message", ""):
                    raise
                statuses[n] = "DELETE_COMPLETE"
        if all(s == "DELETE_COMPLETE" for s in statuses.values()):
            return statuses
        if any(s == "DELETE_FAILED" for s in statuses.values()) or time.monotonic() >= deadline:
            if raise_on_leak:
                raise RuntimeError(f"stacks not deleted: {statuses!r}")
            return statuses
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
