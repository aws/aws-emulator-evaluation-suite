"""deploy-elbv2-2-rule-priority-collision-update-rejected."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elbv2-2-rule-priority-collision-update-rejected"
GROUP = "deploy-elbv2-update"
SERVICES = ["elbv2"]

# One CloudFormation stack operation (create / update / rollback) may legitimately take this long:
# an internet-facing ALB plus its VPC takes minutes to create.
_STACK_TIMEOUT_S = 900
# How long the ALB's public data plane may take to converge (DNS for a fresh ALB, then per-node
# config propagation after an update).
_HTTP_CONVERGE_TIMEOUT_S = 420


def _template(*, a_priority: int, a_body: str, ingress: list[str]) -> str:
    """The whole stack, re-rendered for every create/update so each update is an explicit diff.

    The stack owns its VPC, subnets, IGW and security group; no default VPC is used."""
    fixed = lambda status, body: {  # noqa: E731 - tiny local constructor
        "Type": "fixed-response",
        "FixedResponseConfig": {"StatusCode": status, "ContentType": "text/plain", "MessageBody": body},
    }
    return json.dumps(
        {
            "Parameters": {
                "AzA": {"Type": "AWS::EC2::AvailabilityZone::Name"},
                "AzB": {"Type": "AWS::EC2::AvailabilityZone::Name"},
                "LbName": {"Type": "String"},
            },
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": "10.82.0.0/16", "EnableDnsSupport": True, "EnableDnsHostnames": True},
                },
                "Igw": {"Type": "AWS::EC2::InternetGateway"},
                "IgwAttach": {
                    "Type": "AWS::EC2::VPCGatewayAttachment",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
                },
                "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
                "DefaultRoute": {
                    "Type": "AWS::EC2::Route",
                    "DependsOn": "IgwAttach",
                    "Properties": {
                        "RouteTableId": {"Ref": "RouteTable"},
                        "DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": {"Ref": "Igw"},
                    },
                },
                "SubnetA": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.82.1.0/24", "AvailabilityZone": {"Ref": "AzA"}},
                },
                "SubnetB": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.82.2.0/24", "AvailabilityZone": {"Ref": "AzB"}},
                },
                "AssocA": {
                    "Type": "AWS::EC2::SubnetRouteTableAssociation",
                    "Properties": {"SubnetId": {"Ref": "SubnetA"}, "RouteTableId": {"Ref": "RouteTable"}},
                },
                "AssocB": {
                    "Type": "AWS::EC2::SubnetRouteTableAssociation",
                    "Properties": {"SubnetId": {"Ref": "SubnetB"}, "RouteTableId": {"Ref": "RouteTable"}},
                },
                "Sg": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real behavioral check: inbound HTTP to the ALB under test",
                        "VpcId": {"Ref": "Vpc"},
                        "SecurityGroupIngress": [
                            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": c} for c in ingress
                        ],
                    },
                },
                "Alb": {
                    "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    "DependsOn": ["DefaultRoute", "AssocA", "AssocB"],
                    "Properties": {
                        "Name": {"Ref": "LbName"},
                        "Type": "application",
                        "Scheme": "internet-facing",
                        "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                        "SecurityGroups": [{"Ref": "Sg"}],
                    },
                },
                "Listener": {
                    "Type": "AWS::ElasticLoadBalancingV2::Listener",
                    "Properties": {
                        "LoadBalancerArn": {"Ref": "Alb"},
                        "Port": 80,
                        "Protocol": "HTTP",
                        "DefaultActions": [fixed("404", "no-match")],
                    },
                },
                "RuleA": {
                    "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                    "Properties": {
                        "ListenerArn": {"Ref": "Listener"},
                        "Priority": a_priority,
                        "Conditions": [{"Field": "path-pattern", "Values": ["/a"]}],
                        "Actions": [fixed("200", a_body)],
                    },
                },
                "RuleB": {
                    "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                    "Properties": {
                        "ListenerArn": {"Ref": "Listener"},
                        "Priority": 20,
                        "Conditions": [{"Field": "path-pattern", "Values": ["/a"]}],
                        "Actions": [fixed("200", "b1")],
                    },
                },
            },
            "Outputs": {
                "AlbDns": {"Value": {"Fn::GetAtt": ["Alb", "DNSName"]}},
                "ListenerArn": {"Value": {"Ref": "Listener"}},
                "RuleAArn": {"Value": {"Ref": "RuleA"}},
                "RuleBArn": {"Value": {"Ref": "RuleB"}},
            },
        }
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A stack update moving a ListenerRule onto a taken priority fails and rolls back, leaving the
    rule's ARN, priority and live HTTP body unchanged; moving it to a free priority then succeeds
    and changes the served body on the same rule ARN."""
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
            ]
        )["AvailabilityZones"]
    )
    assert len(zones) >= 2, f"an internet-facing ALB needs two AZs; region {ctx.region!r} offers {zones!r}"

    base = ctx.unique_name("sim2real-")  # 21 chars: fits the 32-char ALB name limit
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    params = [
        {"ParameterKey": "AzA", "ParameterValue": zones[0]},
        {"ParameterKey": "AzB", "ParameterValue": zones[1]},
        {"ParameterKey": "LbName", "ParameterValue": base},
    ]
    stack_tags = [{"Key": "sim2real", "Value": CHECK}]
    ingress = ctx.ingress_cidrs()

    # Registered BEFORE create_stack: resolves the stack by name at teardown time and is a no-op if
    # the create never landed, so no abort between create and registration can strand the stack.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_name))

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(a_priority=10, a_body="a1", ingress=ingress),
        Parameters=params,
        Tags=stack_tags,
    )
    stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}: {_failed_events(cfn, stack_id)!r}"
    out1 = _outputs(cfn, stack_id)
    url_a = f"http://{out1['AlbDns']}/a"
    rule_a, rule_b = out1["RuleAArn"], out1["RuleBArn"]
    _poll_stable(ctx, url_a, 200, "a1")  # priority 10 beats 20 on live traffic

    # ---- The fault: RuleA 10 -> 20 (RuleB's priority) and body a1 -> a2, in one update.
    update_started = cfn.describe_stack_events(StackName=stack_id)["StackEvents"][0]["EventId"]
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(a_priority=20, a_body="a2", ingress=ingress),
        Parameters=params,
        Tags=stack_tags,
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"a colliding-priority update must roll back, ended {status!r}: {_failed_events(cfn, stack_id)!r}"
    )
    reasons = [
        e.get("ResourceStatusReason") or ""
        for e in _events_since(cfn, stack_id, update_started)
        if e["LogicalResourceId"] == "RuleA" and e["ResourceStatus"] == "UPDATE_FAILED"
    ]
    assert reasons, f"no UPDATE_FAILED event for RuleA; failures were {_failed_events(cfn, stack_id)!r}"
    # The resource handler classifies the collision with CloudFormation's closed HandlerErrorCode
    # vocabulary; the elbv2 prose inside the reason ("One or more priorities not found") is not a
    # code and is not asserted.
    codes = [m.group(1) for m in (re.search(r"HandlerErrorCode: ([A-Za-z]+)", r) for r in reasons) if m]
    assert codes == ["AlreadyExists"], f"RuleA update failure codes {codes!r} from reasons {reasons!r}"

    # Effect absent: same rule, same priority, same body — on the control plane and on the wire.
    assert _outputs(cfn, stack_id)["RuleAArn"] == rule_a, "rollback replaced RuleA"
    rules = _rules_by_arn(elbv2, out1["ListenerArn"])
    assert set(rules) - {r for r, v in rules.items() if v["IsDefault"]} == {rule_a, rule_b}, (
        f"rollback left an unexpected rule set: {sorted(rules)!r}"
    )
    assert rules[rule_a]["Priority"] == "10", f"RuleA priority after rollback {rules[rule_a]['Priority']!r}"
    body_a = rules[rule_a]["Actions"][0]["FixedResponseConfig"]["MessageBody"]
    assert body_a == "a1", f"RuleA body after rollback is {body_a!r}; the failed update leaked its body change"
    assert rules[rule_b]["Priority"] == "20", f"RuleB priority disturbed: {rules[rule_b]['Priority']!r}"
    _poll_stable(ctx, url_a, 200, "a1")

    # ---- Positive control: the same rule to a FREE priority (15) with the new body succeeds.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(a_priority=15, a_body="a2", ingress=ingress),
        Parameters=params,
        Tags=stack_tags,
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"free-priority update ended {status!r}: {_failed_events(cfn, stack_id)!r}"
    assert _outputs(cfn, stack_id)["RuleAArn"] == rule_a, "an in-place priority update replaced RuleA"
    rules = _rules_by_arn(elbv2, out1["ListenerArn"])
    assert rules[rule_a]["Priority"] == "15", f"RuleA priority {rules[rule_a]['Priority']!r}, expected '15'"
    _poll_stable(ctx, url_a, 200, "a2")


def _wait_stack(cfn, stack_id, *, timeout_s=_STACK_TIMEOUT_S, interval_s=10.0):
    """Poll a stack (by id, so DELETE_COMPLETE stays readable) until it leaves *_IN_PROGRESS."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} still {status!r} after {timeout_s}s")


def _events_since(cfn, stack_id, event_id):
    """Stack events newer than event_id (events are returned newest first)."""
    newer, token = [], None
    while True:
        kw = {"StackName": stack_id}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_events(**kw)
        for e in page["StackEvents"]:
            if e["EventId"] == event_id:
                return newer
            newer.append(e)
        token = page.get("NextToken")
        if not token:
            return newer


def _failed_events(cfn, stack_id):
    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ][:6]


def _outputs(cfn, stack_id):
    desc = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _rules_by_arn(elbv2, listener_arn):
    rules, marker = [], None
    while True:
        kw = {"ListenerArn": listener_arn}
        if marker:
            kw["Marker"] = marker
        page = elbv2.describe_rules(**kw)
        rules.extend(page["Rules"])
        marker = page.get("NextMarker")
        if not marker:
            return {r["RuleArn"]: r for r in rules}


def _http_get(ctx, url):
    """(status, body) for any HTTP answer; None when nothing answered (DNS, connect, timeout)."""
    try:
        _url, _route = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _poll_stable(ctx, url, want_status, want_body, *, consecutive=5, timeout_s=_HTTP_CONVERGE_TIMEOUT_S, interval_s=3.0):
    """Wait until `consecutive` back-to-back GETs all answer want_status and want_body.

    Each ALB node converges on a rule change on its own clock, so one match is not convergence."""
    deadline = time.monotonic() + timeout_s
    streak, history = 0, []
    while time.monotonic() < deadline:
        status, body = _http_get(ctx, url)
        history = (history + [(status, body[:60])])[-8:]
        if status == want_status and body == want_body:
            streak += 1
            if streak >= consecutive:
                return
        else:
            streak = 0
        time.sleep(interval_s)
    raise AssertionError(
        f"GET {url} never served {want_status} {want_body!r} {consecutive}x in a row within "
        f"{timeout_s}s; last answers {history!r}"
    )


def _teardown_stack(cfn, stack_name):
    """Delete the stack if it exists and wait for it. A failure raises."""
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except ClientError as err:
        if not (
            err.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in err.response["Error"].get("Message", "")
        ):
            raise
        return
    stack_id = stacks[0]["StackId"]
    try:
        cfn.delete_stack(StackName=stack_id)
        status = _wait_stack(cfn, stack_id)
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_name} delete did not finish: {exc}") from exc
    if status != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_name} ended {status}: {_failed_events(cfn, stack_id)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
