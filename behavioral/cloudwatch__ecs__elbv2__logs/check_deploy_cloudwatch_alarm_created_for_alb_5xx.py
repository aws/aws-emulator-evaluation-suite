"""deploy-cloudwatch-alarm-created-for-alb-5xx."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-cloudwatch-alarm-created-for-alb-5xx"
GROUP = "iac-full-stack"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN stack wires a CloudWatch alarm to an ALB's HTTPCode_Target_5XX_Count metric with the
    correct LoadBalancer dimension; forcing the alarm through ALARM->OK via SetAlarmState is
    reflected in DescribeAlarms and recorded in the alarm's state-transition history."""
    template = json.dumps(_template())
    deployed = _deploy_cfn(ctx, template, timeout_s=300.0)
    outputs = deployed["outputs"]
    alarm_name = outputs["AlarmName"]
    alb_arn = outputs["AlbArn"]
    expected_dim_value = alb_arn.split("loadbalancer/", 1)[1]

    cloudwatch = ctx.client("cloudwatch")

    described = cloudwatch.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert described["Namespace"] == "AWS/ApplicationELB", (
        f"expected namespace AWS/ApplicationELB, got {described['Namespace']!r}"
    )
    assert described["MetricName"] == "HTTPCode_Target_5XX_Count", (
        f"expected metric HTTPCode_Target_5XX_Count, got {described['MetricName']!r}"
    )
    dims = {d["Name"]: d["Value"] for d in described["Dimensions"]}
    assert dims.get("LoadBalancer") == expected_dim_value, (
        f"expected LoadBalancer dimension {expected_dim_value!r}, got {dims.get('LoadBalancer')!r}"
    )

    cloudwatch.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real behavioral test"
    )
    _poll_until(
        lambda: cloudwatch.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "ALARM",
        timeout_s=60.0,
        interval_s=3.0,
        description=f"alarm {alarm_name} transitions to ALARM",
    )

    def _has_transition(items, state_value):
        for i in items:
            data = json.loads(i.get("HistoryData", "{}"))
            new_state = data.get("newState", {}).get("stateValue")
            if new_state == state_value:
                return True
            if state_value in i.get("HistorySummary", ""):
                return True
        return False

    _poll_until(
        lambda: cloudwatch.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=20
        )["AlarmHistoryItems"],
        lambda items: _has_transition(items, "ALARM"),
        timeout_s=60.0,
        interval_s=3.0,
        description=f"alarm history for {alarm_name} records the ALARM transition",
    )

    cloudwatch.set_alarm_state(
        AlarmName=alarm_name, StateValue="OK", StateReason="sim2real behavioral test reset"
    )
    _poll_until(
        lambda: cloudwatch.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"],
        lambda s: s == "OK",
        timeout_s=60.0,
        interval_s=3.0,
        description=f"alarm {alarm_name} transitions back to OK",
    )

    _poll_until(
        lambda: cloudwatch.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=20
        )["AlarmHistoryItems"],
        lambda items: _has_transition(items, "OK"),
        timeout_s=60.0,
        interval_s=3.0,
        description=f"alarm history for {alarm_name} records the OK transition",
    )


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                },
            },
            "Igw": {"Type": "AWS::EC2::InternetGateway"},
            "IgwAttach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": False,
                },
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.0.2.0/24",
                    "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": False,
                },
            },
            "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
            "Route": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "IgwAttach",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "Igw"},
                },
            },
            "AssocA": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "SubnetA"}, "RouteTableId": {"Ref": "RouteTable"}},
            },
            "AssocB": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "SubnetB"}, "RouteTableId": {"Ref": "RouteTable"}},
            },
            "AlbSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "alb sg",
                    "VpcId": {"Ref": "Vpc"},
                },
            },
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                    "SecurityGroups": [{"Ref": "AlbSg"}],
                },
            },
            "Tg": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "Port": 80,
                    "Protocol": "HTTP",
                    "TargetType": "ip",
                    "VpcId": {"Ref": "Vpc"},
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Alb"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "Tg"}}],
                },
            },
            "Alarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "DependsOn": "Alb",
                "Properties": {
                    "AlarmDescription": "5xx from targets behind the ALB",
                    "Namespace": "AWS/ApplicationELB",
                    "MetricName": "HTTPCode_Target_5XX_Count",
                    "Dimensions": [
                        {
                            "Name": "LoadBalancer",
                            "Value": {
                                "Fn::Select": [1, {"Fn::Split": ["loadbalancer/", {"Ref": "Alb"}]}]
                            },
                        }
                    ],
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "notBreaching",
                },
            },
        },
        "Outputs": {
            "AlarmName": {"Value": {"Ref": "Alarm"}},
            "AlbArn": {"Value": {"Ref": "Alb"}},
        },
    }


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
