"""deploy-elbv2-1-rule-update-tg-replace-deletion-protection."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elbv2-1-rule-update-tg-replace-deletion-protection"
GROUP = "deploy-elbv2-update"
SERVICES = ["elbv2"]

# One CloudFormation stack operation (create / update / delete) may legitimately take this long:
# an internet-facing ALB plus its VPC takes minutes to create, and a VPC delete waits for the
# ALB's ENIs to be released.
_STACK_TIMEOUT_S = 900
# How long the ALB's public data plane may take to converge on a new rule set (DNS for a fresh
# ALB, then per-node config propagation after an update).
_HTTP_CONVERGE_TIMEOUT_S = 420


def _template(
    *, first_priority: int, first_body: str, tg_name: str, deletion_protection: bool, ingress: list[str]
) -> str:
    """The whole stack, re-rendered for every create/update so each update is an explicit diff.

    The stack owns its VPC, subnets, IGW and security group; no default VPC is used."""
    fixed = lambda body: {  # noqa: E731 - tiny local constructor
        "Type": "fixed-response",
        "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": body},
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
                    "Properties": {"CidrBlock": "10.81.0.0/16", "EnableDnsSupport": True, "EnableDnsHostnames": True},
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
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.81.1.0/24", "AvailabilityZone": {"Ref": "AzA"}},
                },
                "SubnetB": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.81.2.0/24", "AvailabilityZone": {"Ref": "AzB"}},
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
                        "LoadBalancerAttributes": [
                            {
                                "Key": "deletion_protection.enabled",
                                "Value": "true" if deletion_protection else "false",
                            }
                        ],
                    },
                },
                "Tg": {
                    "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                    "Properties": {
                        "Name": tg_name,
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
                "RuleFirst": {
                    "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                    "Properties": {
                        "ListenerArn": {"Ref": "Listener"},
                        "Priority": first_priority,
                        "Conditions": [{"Field": "path-pattern", "Values": ["/a"]}],
                        "Actions": [fixed(first_body)],
                    },
                },
                "RuleSecond": {
                    "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                    "Properties": {
                        "ListenerArn": {"Ref": "Listener"},
                        "Priority": 50,
                        "Conditions": [{"Field": "path-pattern", "Values": ["/a"]}],
                        "Actions": [fixed("v2")],
                    },
                },
            },
            "Outputs": {
                "AlbArn": {"Value": {"Ref": "Alb"}},
                "AlbDns": {"Value": {"Fn::GetAtt": ["Alb", "DNSName"]}},
                "ListenerArn": {"Value": {"Ref": "Listener"}},
                "TgArn": {"Value": {"Ref": "Tg"}},
                "RuleFirstArn": {"Value": {"Ref": "RuleFirst"}},
                "RuleSecondArn": {"Value": {"Ref": "RuleSecond"}},
                "VpcId": {"Value": {"Ref": "Vpc"}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation ALB: an in-place rule update keeps the rule ARN while live traffic changes,
    a TargetGroup rename replaces the group under the listener, and deletion protection turns a
    stack delete into DELETE_FAILED with the ALB still serving until protection is lifted."""
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    # Every decidable precondition before the first create: two available, no-opt-in AZs.
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

    base = ctx.unique_name("sim2real-")  # 21 chars: fits the 32-char ALB / target-group name limits
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    tg_name_old, tg_name_new = f"{base}-a", f"{base}-b"
    params = [
        {"ParameterKey": "AzA", "ParameterValue": zones[0]},
        {"ParameterKey": "AzB", "ParameterValue": zones[1]},
        {"ParameterKey": "LbName", "ParameterValue": base},
    ]
    stack_tags = [{"Key": "sim2real", "Value": CHECK}]
    ingress = ctx.ingress_cidrs()

    # Teardown is registered BEFORE create_stack: it resolves the stack by name at teardown time
    # and is a no-op if the create never landed, so no abort between create and registration can
    # strand the stack. It lifts deletion protection first, because the check deliberately turns
    # protection on and an abort in that window would otherwise leave an undeletable stack.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, elbv2, stack_name))

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first_priority=10, first_body="v1", tg_name=tg_name_old, deletion_protection=False, ingress=ingress),
        Parameters=params,
        Tags=stack_tags,
    )
    stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}: {_failed_events(cfn, stack_id)!r}"
    out1 = _outputs(cfn, stack_id)
    url_a = f"http://{out1['AlbDns']}/a"
    url_default = f"http://{out1['AlbDns']}/unmatched"

    # ---- 1. Two rules match /a; the LOWER priority number (10) wins on live traffic.
    rules = _rules_by_arn(elbv2, out1["ListenerArn"])
    assert rules[out1["RuleFirstArn"]]["Priority"] == "10", f"RuleFirst priority {rules[out1['RuleFirstArn']]!r}"
    assert rules[out1["RuleSecondArn"]]["Priority"] == "50", f"RuleSecond priority {rules[out1['RuleSecondArn']]!r}"
    _poll_stable(ctx, url_a, 200, "v1")
    # The default action forwards to a target group with no targets: the ALB itself answers 503.
    _poll_stable(ctx, url_default, 503, None)

    # ---- 2. In-place update: RuleFirst body v1 -> v1b and priority 10 -> 5. Same rule ARN.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(first_priority=5, first_body="v1b", tg_name=tg_name_old, deletion_protection=False, ingress=ingress),
        Parameters=params,
        Tags=stack_tags,
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"update #1 ended {status!r}: {_failed_events(cfn, stack_id)!r}"
    out2 = _outputs(cfn, stack_id)
    assert out2["RuleFirstArn"] == out1["RuleFirstArn"], (
        f"in-place rule update replaced the rule: ARN {out1['RuleFirstArn']!r} -> {out2['RuleFirstArn']!r}"
    )
    assert out2["RuleSecondArn"] == out1["RuleSecondArn"], (
        f"untouched RuleSecond changed ARN {out1['RuleSecondArn']!r} -> {out2['RuleSecondArn']!r}"
    )
    rules = _rules_by_arn(elbv2, out2["ListenerArn"])
    first = rules.get(out1["RuleFirstArn"])
    assert first is not None, f"rule {out1['RuleFirstArn']!r} vanished after an in-place update; rules={rules!r}"
    assert first["Priority"] == "5", f"describe_rules shows priority {first['Priority']!r}, expected '5'"
    first_body = first["Actions"][0]["FixedResponseConfig"]["MessageBody"]
    assert first_body == "v1b", f"describe_rules shows body {first_body!r}, expected 'v1b'"
    _poll_stable(ctx, url_a, 200, "v1b")

    # ---- 3. Replacement-forcing update: the TargetGroup Name is immutable.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(first_priority=5, first_body="v1b", tg_name=tg_name_new, deletion_protection=False, ingress=ingress),
        Parameters=params,
        Tags=stack_tags,
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"update #2 ended {status!r}: {_failed_events(cfn, stack_id)!r}"
    out3 = _outputs(cfn, stack_id)
    old_tg, new_tg = out1["TgArn"], out3["TgArn"]
    assert new_tg != old_tg, f"a TargetGroup Name change must replace the group, but the ARN stayed {old_tg!r}"
    new_desc = elbv2.describe_target_groups(TargetGroupArns=[new_tg])["TargetGroups"][0]
    assert new_desc["TargetGroupName"] == tg_name_new, f"replacement group name {new_desc['TargetGroupName']!r}"
    listener = elbv2.describe_listeners(ListenerArns=[out3["ListenerArn"]])["Listeners"][0]
    assert out3["ListenerArn"] == out1["ListenerArn"], (
        f"the listener was replaced {out1['ListenerArn']!r} -> {out3['ListenerArn']!r}; it should update in place"
    )
    default_tg = listener["DefaultActions"][0].get("TargetGroupArn")
    assert default_tg == new_tg, f"listener default action forwards to {default_tg!r}, expected the new group {new_tg!r}"
    code, message = _error(lambda: elbv2.describe_target_groups(TargetGroupArns=[old_tg]))
    assert code == "TargetGroupNotFound", f"old target group {old_tg!r} should be deleted; describe gave {code!r}"
    assert message == "One or more target groups not found", f"describe_target_groups MESSAGE={message!r}"
    # The rules are untouched by the group swap, and the data plane still serves the winner.
    _poll_stable(ctx, url_a, 200, "v1b")
    _poll_stable(ctx, url_default, 503, None)

    # ---- 4. Deletion protection, set through the stack so CFN's view stays the source of truth.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(first_priority=5, first_body="v1b", tg_name=tg_name_new, deletion_protection=True, ingress=ingress),
        Parameters=params,
        Tags=stack_tags,
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"update #3 ended {status!r}: {_failed_events(cfn, stack_id)!r}"
    alb_arn = out1["AlbArn"]
    assert _outputs(cfn, stack_id)["AlbArn"] == alb_arn, "an attribute change must not replace the ALB"
    attrs = _lb_attrs(elbv2, alb_arn)
    assert attrs.get("deletion_protection.enabled") == "true", f"deletion protection not on: {attrs!r}"

    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id)
    assert status == "DELETE_FAILED", (
        f"a stack whose ALB has deletion protection must end DELETE_FAILED, got {status!r}"
    )
    res = {
        r["LogicalResourceId"]: r
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }
    assert res["Alb"]["ResourceStatus"] == "DELETE_FAILED", (
        f"the ALB resource should be the one that failed to delete, got {res['Alb']!r}"
    )
    lb = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]
    assert lb["State"]["Code"] == "active", f"protected ALB should still be active, got {lb['State']!r}"
    assert _lb_attrs(elbv2, alb_arn).get("deletion_protection.enabled") == "true", "protection silently dropped"

    # A stack in DELETE_FAILED accepts no update — so protection cannot be lifted through the
    # stack. Exact error, and the stack must be left exactly where it was.
    code, message = _error(
        lambda: cfn.update_stack(
            StackName=stack_id,
            TemplateBody=_template(
                first_priority=5, first_body="v1b", tg_name=tg_name_new, deletion_protection=False,
                ingress=ingress,
            ),
            Parameters=params,
            Tags=stack_tags,
        )
    )
    assert code == "ValidationError", f"update_stack on a DELETE_FAILED stack gave {code!r}, expected ValidationError"
    assert message == f"Stack:{stack_id} is in DELETE_FAILED state and can not be updated.", f"update_stack MESSAGE={message!r}"
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "DELETE_FAILED", f"a rejected update moved the stack to {status!r}"

    # ---- 5. Lift protection on the resource itself, then the retried delete completes.
    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=alb_arn, Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}]
    )
    assert _lb_attrs(elbv2, alb_arn).get("deletion_protection.enabled") == "false", "protection still on"
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id)
    assert status == "DELETE_COMPLETE", f"retried delete ended {status!r}: {_failed_events(cfn, stack_id)!r}"

    # ---- 6. Nothing the stack owned survives.
    code, message = _error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn]))
    assert code == "LoadBalancerNotFound", f"deleted ALB {alb_arn!r}: describe gave {code!r}"
    assert message == "One or more load balancers not found", f"describe_load_balancers MESSAGE={message!r}"
    code, message = _error(lambda: elbv2.describe_target_groups(TargetGroupArns=[new_tg]))
    assert code == "TargetGroupNotFound", f"deleted target group {new_tg!r}: describe gave {code!r}"
    assert message == "One or more target groups not found", f"describe_target_groups MESSAGE={message!r}"
    code, message = _error(lambda: ec2.describe_vpcs(VpcIds=[out1["VpcId"]]))
    assert code == "InvalidVpcID.NotFound", f"stack VPC {out1['VpcId']!r}: describe gave {code!r}"
    assert message == f"The vpc ID '{out1['VpcId']}' does not exist", f"describe_vpcs MESSAGE={message!r}"


def _error(fn):
    """The AWS error (code, message) fn raised. A call that SUCCEEDS is itself the finding, so it raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


def _lb_attrs(elbv2, lb_arn):
    attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)["Attributes"]
    return {a["Key"]: a["Value"] for a in attrs}


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
    """Wait until `consecutive` back-to-back GETs all answer want_status (and want_body, if given).

    Each ALB node converges on a rule change on its own clock, so one match is not convergence."""
    deadline = time.monotonic() + timeout_s
    streak, history = 0, []
    while time.monotonic() < deadline:
        status, body = _http_get(ctx, url)
        history = (history + [(status, body[:60])])[-8:]
        if status == want_status and (want_body is None or body == want_body):
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


def _teardown_stack(cfn, elbv2, stack_name):
    """Delete the stack if it exists, lifting ALB deletion protection first. Never raises."""
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
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]:
            if r["LogicalResourceId"] == "Alb" and r.get("PhysicalResourceId", "").startswith("arn:"):
                elbv2.modify_load_balancer_attributes(
                    LoadBalancerArn=r["PhysicalResourceId"],
                    Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}],
                )
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("LoadBalancerNotFound",) or
            (exc.response["Error"]["Code"] == "ValidationError"
             and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise
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
