"""deploy-elbv2-2-duplicate-rule-priority-rejected-rolls-back-stack."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elbv2-2-duplicate-rule-priority-rejected-rolls-back-stack"
GROUP = "deploy-elbv2-rollback"
SERVICES = ["cloudformation", "elbv2"]

# Data-plane failure marker: an ALB that reached CREATE_COMPLETE but never answers HTTP is a
# defect of the target, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_FIRST_PRIORITY = 10
_CLASH_PRIORITY = 10  # the broken stack: SecondRule reuses FirstRule's priority
_FREE_PRIORITY = 20  # the twin control stack: every priority unique
_TEMPLATE_IDLE = "60"
_DRIFTED_IDLE = "120"
_STACK_TIMEOUT_S = 900.0


def _fixed(status: str, body) -> list:
    return [
        {
            "Type": "fixed-response",
            "FixedResponseConfig": {"StatusCode": status, "ContentType": "text/plain", "MessageBody": body},
        }
    ]


def _template(second_priority: int, ingress: list[str]) -> str:
    """VPC + IGW + 2 public subnets + internet-facing ALB, Listener, TargetGroup, two ListenerRules.

    Everything the ALB needs is built inside the stack (no ambient default VPC). SecondRule
    DependsOn FirstRule, so on a priority collision it is deterministically SecondRule that fails.
    """
    tag = [{"Key": "sim2real", "Value": "behavioral"}]
    subnet = lambda idx, cidr: {  # noqa: E731
        "Type": "AWS::EC2::Subnet",
        "Properties": {
            "VpcId": {"Ref": "Vpc"},
            "CidrBlock": cidr,
            "AvailabilityZone": {"Fn::Select": [idx, {"Fn::GetAZs": ""}]},
            "Tags": tag,
        },
    }
    assoc = lambda sn: {  # noqa: E731
        "Type": "AWS::EC2::SubnetRouteTableAssociation",
        "Properties": {"SubnetId": {"Ref": sn}, "RouteTableId": {"Ref": "RouteTable"}},
    }
    return json.dumps(
        {
            "Parameters": {"Body": {"Type": "String"}},
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": "10.80.0.0/16", "EnableDnsSupport": True,
                                   "EnableDnsHostnames": True, "Tags": tag},
                },
                "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": tag}},
                "IgwAttach": {
                    "Type": "AWS::EC2::VPCGatewayAttachment",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
                },
                "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": tag}},
                "DefaultRoute": {
                    "Type": "AWS::EC2::Route",
                    "DependsOn": "IgwAttach",
                    "Properties": {"RouteTableId": {"Ref": "RouteTable"}, "DestinationCidrBlock": "0.0.0.0/0",
                                   "GatewayId": {"Ref": "Igw"}},
                },
                "SubnetA": subnet(0, "10.80.1.0/24"),
                "SubnetB": subnet(1, "10.80.2.0/24"),
                "AssocA": assoc("SubnetA"),
                "AssocB": assoc("SubnetB"),
                "AlbSg": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real deploy-elbv2-rollback ALB ingress",
                        "VpcId": {"Ref": "Vpc"},
                        "SecurityGroupIngress": [
                            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": c} for c in ingress
                        ],
                        "Tags": tag,
                    },
                },
                "Alb": {
                    "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                    "DependsOn": ["IgwAttach", "DefaultRoute", "AssocA", "AssocB"],
                    "Properties": {
                        "Type": "application",
                        "Scheme": "internet-facing",
                        "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                        "SecurityGroups": [{"Ref": "AlbSg"}],
                        "LoadBalancerAttributes": [
                            {"Key": "idle_timeout.timeout_seconds", "Value": _TEMPLATE_IDLE}
                        ],
                        "Tags": tag,
                    },
                },
                "TargetGroup": {
                    "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                    "Properties": {"Protocol": "HTTP", "Port": 80, "VpcId": {"Ref": "Vpc"},
                                   "TargetType": "ip", "Tags": tag},
                },
                "Listener": {
                    "Type": "AWS::ElasticLoadBalancingV2::Listener",
                    "Properties": {
                        "LoadBalancerArn": {"Ref": "Alb"},
                        "Port": 80,
                        "Protocol": "HTTP",
                        "DefaultActions": _fixed("404", "no-match"),
                    },
                },
                "FirstRule": {
                    "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                    "Properties": {
                        "ListenerArn": {"Ref": "Listener"},
                        "Priority": _FIRST_PRIORITY,
                        "Conditions": [{"Field": "path-pattern", "Values": ["/hello"]}],
                        "Actions": _fixed("200", {"Ref": "Body"}),
                    },
                },
                "SecondRule": {
                    "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                    "DependsOn": "FirstRule",
                    "Properties": {
                        "ListenerArn": {"Ref": "Listener"},
                        "Priority": second_priority,
                        "Conditions": [{"Field": "path-pattern", "Values": ["/other"]}],
                        "Actions": _fixed("200", "other"),
                    },
                },
            },
            "Outputs": {
                "AlbArn": {"Value": {"Ref": "Alb"}},
                "AlbDns": {"Value": {"Fn::GetAtt": ["Alb", "DNSName"]}},
                "TargetGroupArn": {"Value": {"Ref": "TargetGroup"}},
                "ListenerArn": {"Value": {"Ref": "Listener"}},
            },
        }
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A ListenerRule reusing an occupied priority fails with ELBv2's PriorityInUse message and
    rolls the whole stack back, while a twin with unique priorities serves HTTP, starts IN_SYNC,
    and reports DRIFTED after an out-of-band idle-timeout change.
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")
    body = ctx.unique_name("sim2real-body-")
    params = [{"ParameterKey": "Body", "ParameterValue": body}]
    ingress = ctx.ingress_cidrs()

    broken = ctx.unique_name("sim2real-xsvc-elbrb-")
    cfn.create_stack(
        StackName=broken, TemplateBody=_template(_CLASH_PRIORITY, ingress), Parameters=params,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_stacks(cfn, [broken]))

    control = ctx.unique_name("sim2real-xsvc-elbok-")
    cfn.create_stack(
        StackName=control, TemplateBody=_template(_FREE_PRIORITY, ingress), Parameters=params,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    # ONE net that issues BOTH deletes before it waits for either to reach DELETE_COMPLETE.
    ctx.on_cleanup(lambda: _delete_stacks(cfn, [control, broken]))

    # ---- the broken stack: fails at SecondRule, rolls everything back ----
    broken_status = _wait_stack_settled(cfn, broken)
    assert broken_status == "ROLLBACK_COMPLETE", (
        f"a stack whose rule collides on priority must end ROLLBACK_COMPLETE, got {broken_status!r}"
    )
    events = sorted(_stack_events(cfn, broken), key=lambda e: e["Timestamp"])
    failed = [e for e in events if e["ResourceStatus"] == "CREATE_FAILED"]
    assert failed, f"no CREATE_FAILED event at all; events were {_brief(events)!r}"
    first_failed = failed[0]
    assert first_failed["LogicalResourceId"] == "SecondRule", (
        f"the FIRST resource to fail must be SecondRule (the priority clash), got "
        f"{first_failed['LogicalResourceId']!r}: {first_failed.get('ResourceStatusReason')!r}"
    )
    # Real AWS (the ListenerRule resource handler) reports the ELBv2 exception MESSAGE, its service
    # and HTTP status, plus a handler error code -- it does NOT spell the token "PriorityInUse".
    # Parse the fields structurally; the PriorityInUse code is tied to this message further down by
    # provoking the same collision through the ELBv2 API directly.
    reason = first_failed.get("ResourceStatusReason") or ""
    m = re.search(
        r'Resource handler returned message: "(?P<msg>.*?) \(Service: (?P<svc>[A-Za-z0-9]+), '
        r"Status Code: (?P<status>\d+)",
        reason,
    )
    assert m, f"SecondRule's failure reason carries no resource-handler message: {reason!r}"
    clash_msg = f"Priority '{_CLASH_PRIORITY}' is currently in use"
    assert (m["msg"], m["svc"], m["status"]) == (clash_msg, "ElasticLoadBalancingV2", "400"), (
        f"SecondRule must fail on ELBv2's priority-in-use 400 {clash_msg!r}, got "
        f"{(m['msg'], m['svc'], m['status'])!r} in {reason!r}"
    )
    h = re.search(r"HandlerErrorCode: (?P<code>[A-Za-z]+)", reason)
    assert h and h["code"] == "AlreadyExists", (
        f"the handler must classify the clash as AlreadyExists, got {h and h['code']!r} in {reason!r}"
    )

    created = {}
    for logical in ("Alb", "TargetGroup", "Listener", "FirstRule"):
        done = [e for e in events if e["LogicalResourceId"] == logical and e["ResourceStatus"] == "CREATE_COMPLETE"]
        assert done, (
            f"{logical} never reached CREATE_COMPLETE before the clash, so rollback proves nothing; "
            f"its events were {_brief(e for e in events if e['LogicalResourceId'] == logical)!r}"
        )
        created[logical] = done[-1]["PhysicalResourceId"]
        deleted = [e for e in events if e["LogicalResourceId"] == logical and e["ResourceStatus"] == "DELETE_COMPLETE"]
        assert deleted, f"rollback never reported DELETE_COMPLETE for {logical} ({created[logical]!r})"

    code = _error_code(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[created["Alb"]]))
    assert code == ("LoadBalancerNotFound", "One or more load balancers not found"), (
        f"the rolled-back ALB {created['Alb']!r} must be gone (LoadBalancerNotFound), got {code!r}"
    )
    code = _error_code(lambda: elbv2.describe_target_groups(TargetGroupArns=[created["TargetGroup"]]))
    assert code == ("TargetGroupNotFound", "One or more target groups not found"), (
        f"the rolled-back TargetGroup {created['TargetGroup']!r} must be gone (TargetGroupNotFound), got {code!r}"
    )
    code = _error_code(lambda: elbv2.describe_listeners(ListenerArns=[created["Listener"]]))
    assert code == ("ListenerNotFound", "One or more listeners not found"), (
        f"the rolled-back Listener {created['Listener']!r} must be gone (ListenerNotFound), got {code!r}"
    )
    code = _error_code(lambda: elbv2.describe_rules(RuleArns=[created["FirstRule"]]))
    assert code == ("RuleNotFound", "One or more rules not found"), (
        f"the rolled-back FirstRule {created['FirstRule']!r} must be gone (RuleNotFound), got {code!r}"
    )

    # ---- positive control: the twin stack with unique priorities ----
    control_status = _wait_stack_settled(cfn, control)
    assert control_status == "CREATE_COMPLETE", (
        f"the twin stack with unique priorities must deploy, got {control_status!r}: "
        f"{_brief(e for e in _stack_events(cfn, control) if e['ResourceStatus'].endswith('FAILED'))!r}"
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=control)["Stacks"][0].get("Outputs", [])
    }
    alb_arn = outputs["AlbArn"]
    rules = elbv2.describe_rules(ListenerArn=outputs["ListenerArn"])["Rules"]
    got_prios = sorted(int(r["Priority"]) for r in rules if not r["IsDefault"])
    assert got_prios == [_FIRST_PRIORITY, _FREE_PRIORITY], (
        f"the control listener must carry exactly the two template rules, got priorities {got_prios!r}"
    )

    # The same collision through the ELBv2 API: PriorityInUse, with exactly the message CFN surfaced.
    try:
        stray = elbv2.create_rule(
            ListenerArn=outputs["ListenerArn"],
            Priority=_CLASH_PRIORITY,
            Conditions=[{"Field": "path-pattern", "Values": ["/clash"]}],
            Actions=_fixed("200", "clash"),
        )["Rules"][0]
    except ClientError as exc:
        api_code, api_msg = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        ctx.on_cleanup(lambda: elbv2.delete_rule(RuleArn=stray["RuleArn"]))
        raise AssertionError(f"CreateRule at occupied priority {_CLASH_PRIORITY} SUCCEEDED: {stray!r}")
    assert (api_code, api_msg) == ("PriorityInUse", m["msg"]), (
        f"CreateRule at an occupied priority must raise PriorityInUse with the message CFN reported "
        f"({m['msg']!r}), got {(api_code, api_msg)!r}"
    )
    after = sorted(int(r["Priority"]) for r in elbv2.describe_rules(ListenerArn=outputs["ListenerArn"])["Rules"]
                   if not r["IsDefault"])
    assert after == got_prios, f"the rejected CreateRule changed the listener's rules: {after!r}"

    base = f"http://{outputs['AlbDns']}"
    status, got = _wait_http(ctx, f"{base}/hello", want_status=200, want_body=body)
    assert (status, got) == (200, body), (
        f"{DATAPLANE_MARKER}: GET {base}/hello through the CREATE_COMPLETE ALB must serve the "
        f"FirstRule fixed response 200 {body!r}, last saw {status!r} {got!r}"
    )
    status, got = _http_get(ctx, f"{base}/other")
    assert (status, got) == (200, "other"), f"GET /other must hit SecondRule (200 'other'), got {status!r} {got!r}"
    status, got = _http_get(ctx, f"{base}/unrouted")
    assert (status, got) == (404, "no-match"), (
        f"an unmatched path must fall to the listener default (404 'no-match'), got {status!r} {got!r}"
    )

    # ---- drift: IN_SYNC, then an out-of-band attribute change, then DRIFTED ----
    det = _detect_drift(cfn, control)
    assert (det["DetectionStatus"], det.get("StackDriftStatus")) == ("DETECTION_COMPLETE", "IN_SYNC"), (
        f"a freshly deployed stack must detect IN_SYNC, got {det!r}"
    )

    elbv2.modify_load_balancer_attributes(
        LoadBalancerArn=alb_arn,
        Attributes=[{"Key": "idle_timeout.timeout_seconds", "Value": _DRIFTED_IDLE}],
    )
    live = {
        a["Key"]: a["Value"]
        for a in elbv2.describe_load_balancer_attributes(LoadBalancerArn=alb_arn)["Attributes"]
    }
    assert live.get("idle_timeout.timeout_seconds") == _DRIFTED_IDLE, (
        f"the out-of-band change did not land: idle_timeout is {live.get('idle_timeout.timeout_seconds')!r}"
    )

    det = _detect_drift(cfn, control)
    assert (det["DetectionStatus"], det.get("StackDriftStatus")) == ("DETECTION_COMPLETE", "DRIFTED"), (
        f"after ModifyLoadBalancerAttributes outside CFN the stack must detect DRIFTED, got {det!r}"
    )
    drifts = _resource_drifts(cfn, control)
    modified = {d["LogicalResourceId"]: d for d in drifts if d["StackResourceDriftStatus"] == "MODIFIED"}
    assert set(modified) == {"Alb"}, (
        f"exactly the LoadBalancer must be MODIFIED, got {sorted(modified)!r} "
        f"from {[(d['LogicalResourceId'], d['StackResourceDriftStatus']) for d in drifts]!r}"
    )
    alb_drift = modified["Alb"]
    assert alb_drift["ResourceType"] == "AWS::ElasticLoadBalancingV2::LoadBalancer", (
        f"the MODIFIED resource has type {alb_drift['ResourceType']!r}"
    )
    diffs = alb_drift.get("PropertyDifferences", [])
    attr_diffs = [d for d in diffs if d["PropertyPath"].startswith("/LoadBalancerAttributes")]
    assert attr_diffs, f"no PropertyDifference under /LoadBalancerAttributes: {diffs!r}"
    value_diffs = [
        d for d in attr_diffs
        if (d["ExpectedValue"], d["ActualValue"], d["DifferenceType"]) == (_TEMPLATE_IDLE, _DRIFTED_IDLE, "NOT_EQUAL")
    ]
    assert len(value_diffs) == 1, (
        f"expected one NOT_EQUAL idle-timeout difference {_TEMPLATE_IDLE!r} -> {_DRIFTED_IDLE!r}, got {attr_diffs!r}"
    )
    actual = json.loads(alb_drift["ActualProperties"])
    live_attrs = {a["Key"]: a["Value"] for a in actual.get("LoadBalancerAttributes", [])}
    assert live_attrs.get("idle_timeout.timeout_seconds") == _DRIFTED_IDLE, (
        f"ActualProperties must show the live idle timeout {_DRIFTED_IDLE!r}, got {live_attrs!r}"
    )




def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _brief(events):
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason")) for e in events]


def _stack_events(cfn, stack):
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        out.extend(page["StackEvents"])
    return out


def _wait_stack_settled(cfn, stack):
    deadline = time.monotonic() + _STACK_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(2)
    return status


def _detect_drift(cfn, stack):
    det_id = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    deadline = time.monotonic() + 300
    st = None
    while time.monotonic() < deadline:
        st = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=det_id)
        if st["DetectionStatus"] != "DETECTION_IN_PROGRESS":
            break
        time.sleep(5)
    keep = ("DetectionStatus", "StackDriftStatus", "DetectionStatusReason", "DriftedStackResourceCount")
    return {k: st[k] for k in keep if k in st}


def _resource_drifts(cfn, stack):
    out, token = [], None
    while True:
        kw = {"StackName": stack}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        out.extend(page["StackResourceDrifts"])
        token = page.get("NextToken")
        if not token:
            return out


def _http_get(ctx, url):
    try:
        _url, _route = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10) as resp:  # noqa: S310
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _wait_http(ctx, url, want_status, want_body, timeout_s=300.0):
    """The ALB DNS name can take a minute or two to resolve after CREATE_COMPLETE; poll for it."""
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            last = _http_get(ctx, url)
            if last == (want_status, want_body):
                return last
        except (urllib.error.URLError, OSError) as exc:
            last = (None, f"<error: {exc}>")
        time.sleep(5)
    return last


def _delete_stacks(cfn, stacks, wait_s=600.0):
    """Issue every delete first, then wait for each stack to reach DELETE_COMPLETE; raise otherwise."""
    _leaks: list = []
    for stack in stacks:
        try:
            cfn.delete_stack(StackName=stack)
        except Exception as exc:  # noqa: BLE001 - re-raised
            _leaks.append((f"cloudformation delete_stack({stack!r}) failed: {exc}", exc))
    deadline = time.monotonic() + wait_s
    pending = list(stacks)
    while pending and time.monotonic() < deadline:
        still = []
        for stack in pending:
            try:
                status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
            except ClientError as err:
                if not (
                    err.response["Error"]["Code"] == "ValidationError"
                    and "does not exist" in err.response["Error"].get("Message", "")
                ):
                    raise
                continue
            if status == "DELETE_FAILED":
                _leaks.append((f"cloudformation stack {stack!r} is DELETE_FAILED", None))
            elif status != "DELETE_COMPLETE":
                still.append(stack)
        pending = still
        if pending:
            time.sleep(2)
    for stack in pending:
        _leaks.append((f"cloudformation stack {stack!r} not DELETE_COMPLETE after {wait_s:.0f}s", None))
    if _leaks:
        raise RuntimeError("; ".join(m for m, _ in _leaks)) from next(
            (e for _, e in _leaks if e is not None), None
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
