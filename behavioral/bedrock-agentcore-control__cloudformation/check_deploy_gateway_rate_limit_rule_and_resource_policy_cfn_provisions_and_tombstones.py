"""deploy-gateway-rate-limit-rule-and-resource-policy-cfn-provisions-and-tombstones."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-gateway-rate-limit-rule-and-resource-policy-cfn-provisions-and-tombstones"
GROUP = "deploy"
SERVICES = ["bedrock-agentcore-control", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_GATEWAY_GONE = (
    "ResourceNotFoundException",
    "Failed to retrieve gateway because it doesn't exist. "
    "Retry the request with a different resource identifier.",
)
_LIMIT_DESCRIPTION = "sim2real rate limit"


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "-")


def _policy_sub() -> str:
    """The resource policy as an Fn::Sub string: it names the gateway's own ARN."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Sim2RealAllowSameAccountInvoke",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"},
            "Action": "bedrock-agentcore:InvokeGateway",
            "Resource": "${Gateway.GatewayArn}",
        }],
    })


def _template(gateway_name, target_name, with_children=True):
    resources = {
        "GatewayRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }]},
        }},
        "Gateway": {"Type": "AWS::BedrockAgentCore::Gateway", "Properties": {
            "Name": gateway_name, "RoleArn": {"Fn::GetAtt": ["GatewayRole", "Arn"]},
            "AuthorizerType": "AWS_IAM",
        }},
        "GatewayTarget": {"Type": "AWS::BedrockAgentCore::GatewayTarget", "Properties": {
            "GatewayIdentifier": {"Ref": "Gateway"}, "Name": target_name,
            "TargetConfiguration": {"Http": {"Passthrough": {
                "Endpoint": "https://example.com/mcp", "ProtocolType": "CUSTOM",
            }}},
        }},
    }
    outputs = {
        "GatewayId": {"Value": {"Ref": "Gateway"}},
        "GatewayArn": {"Value": {"Fn::GetAtt": ["Gateway", "GatewayArn"]}},
    }
    if with_children:
        resources.update({
            "GatewayRateLimit": {"Type": "AWS::BedrockAgentCore::GatewayRateLimit", "Properties": {
                "GatewayIdentifier": {"Ref": "Gateway"},
                "Description": _LIMIT_DESCRIPTION,
                "DimensionKeys": ["targetName"],
                "Entries": [{"Dimensions": {"targetName": target_name},
                             "Requests": [{"Rate": 5, "Period": "second"}]}],
            }},
            "GatewayRule": {"Type": "AWS::BedrockAgentCore::GatewayRule",
                            "DependsOn": "GatewayTarget", "Properties": {
                                "GatewayIdentifier": {"Ref": "Gateway"},
                                "Priority": 1,
                                "Actions": [{"RouteToTarget": {
                                    "StaticRoute": {"TargetName": target_name}}}],
                            }},
            "GatewayResourcePolicy": {"Type": "AWS::BedrockAgentCore::ResourcePolicy",
                                      "Properties": {
                                          "ResourceArn": {"Fn::GetAtt": ["Gateway", "GatewayArn"]},
                                          "Policy": {"Fn::Sub": _policy_sub()},
                                      }},
        })
        outputs.update({
            "RateLimitRef": {"Value": {"Ref": "GatewayRateLimit"}},
            "RateLimitStatus": {"Value": {"Fn::GetAtt": ["GatewayRateLimit", "Status"]}},
            "RuleRef": {"Value": {"Ref": "GatewayRule"}},
            "RuleId": {"Value": {"Fn::GetAtt": ["GatewayRule", "RuleId"]}},
            "RuleGatewayArn": {"Value": {"Fn::GetAtt": ["GatewayRule", "GatewayArn"]}},
            "ResourcePolicyRef": {"Value": {"Ref": "GatewayResourcePolicy"}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout_s:.0f}s; last={last!r}")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed GatewayRateLimit, GatewayRule and ResourcePolicy read back through AgentCore.

    Each Ref and GetAtt matches an AgentCore list entry; an update dropping the three children
    removes each one while the gateway still answers, and deleting the stack removes the gateway.
    """
    control = ctx.client("bedrock-agentcore-control")
    cfn = ctx.client("cloudformation")
    gateway_name = _alnum_name(ctx, "sim2realcfnrlgw")
    target_name = _alnum_name(ctx, "sim2realcfnrltgt")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-gw-rl-rule-"),
                            _template(gateway_name, target_name), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    gateway_id, gateway_arn = out["GatewayId"], out["GatewayArn"]
    account = gateway_arn.split(":")[4]

    # Gateway Ref against an independent ListGateways entry found by the template's name.
    listed_gw = [g for g in paginate(control, "list_gateways", "items") if g["name"] == gateway_name]
    assert [g["gatewayId"] for g in listed_gw] == [gateway_id], (
        f"ListGateways by name {gateway_name!r}: {listed_gw!r}; Ref {gateway_id!r}"
    )
    gateway = _poll_until(lambda: control.get_gateway(gatewayIdentifier=gateway_id),
                          lambda r: r["status"] == "READY")
    got_gw = (gateway["gatewayArn"], gateway["name"], gateway["authorizerType"])
    assert got_gw == (gateway_arn, gateway_name, "AWS_IAM"), f"GetGateway {got_gw!r}"

    # Target: found by the template's name in ListGatewayTargets, its templated passthrough read.
    targets = [t for t in paginate(control, "list_gateway_targets", "items",
                                   gatewayIdentifier=gateway_id) if t["name"] == target_name]
    assert len(targets) == 1, f"ListGatewayTargets by name {target_name!r}: {targets!r}"
    target = control.get_gateway_target(gatewayIdentifier=gateway_id,
                                        targetId=targets[0]["targetId"])
    passthrough = target["targetConfiguration"]["http"]["passthrough"]
    got = (target["name"], passthrough["endpoint"], passthrough["protocolType"])
    want = (target_name, "https://example.com/mcp", "CUSTOM")
    assert got == want, f"GetGatewayTarget {got!r}, expected {want!r}"

    # Rate limit: the composite Ref, the Status GetAtt and every templated property, from the list.
    limits = paginate(control, "list_gateway_rate_limits", "rateLimits", gatewayIdentifier=gateway_id)
    assert len(limits) == 1, f"ListGatewayRateLimits on the stack's gateway: {limits!r}"
    limit = limits[0]
    rate_limit_id = limit["rateLimitId"]
    assert out["RateLimitRef"] == f"{gateway_id}|{rate_limit_id}", (
        f"GatewayRateLimit Ref {out['RateLimitRef']!r}; listed id {rate_limit_id!r}"
    )
    assert out["RateLimitStatus"] == limit["status"], (
        f"GetAtt Status {out['RateLimitStatus']!r} != listed status {limit['status']!r}"
    )
    got_limit = control.get_gateway_rate_limit(gatewayIdentifier=gateway_id,
                                               rateLimitId=rate_limit_id)
    got = (got_limit["description"], got_limit["dimensionKeys"], got_limit["entries"])
    want = (_LIMIT_DESCRIPTION, ["targetName"],
            [{"dimensions": {"targetName": target_name},
              "requests": [{"rate": 5.0, "period": "second"}]}])
    assert got == want, f"GetGatewayRateLimit {got!r}, expected {want!r}"

    # Rule: the composite Ref and the RuleId and GatewayArn GetAtts against the list entry.
    rules = paginate(control, "list_gateway_rules", "gatewayRules", gatewayIdentifier=gateway_id)
    own = [r for r in rules if not r.get("system")]
    assert len(own) == 1, f"ListGatewayRules on the stack's gateway: {rules!r}"
    rule_id = own[0]["ruleId"]
    assert (out["RuleRef"], out["RuleId"], out["RuleGatewayArn"]) == (
        f"{gateway_id}|{rule_id}", rule_id, gateway_arn), (
        f"GatewayRule Ref {out['RuleRef']!r}, GetAtt RuleId {out['RuleId']!r}, GatewayArn "
        f"{out['RuleGatewayArn']!r}; listed rule {rule_id!r} on {gateway_arn!r}"
    )
    got_rule = control.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id)
    got = (got_rule["priority"], got_rule["gatewayArn"], got_rule["actions"])
    want = (1, gateway_arn, [{"routeToTarget": {"staticRoute": {"targetName": target_name}}}])
    assert got == want, f"GetGatewayRule {got!r}, expected {want!r}"

    # Resource policy: Ref is the ResourceArn; the stored document is the resolved Fn::Sub.
    assert out["ResourcePolicyRef"] == gateway_arn, (
        f"ResourcePolicy Ref {out['ResourcePolicyRef']!r} != gateway ARN {gateway_arn!r}"
    )
    partition = stack_id.split(":")[1]
    want_policy = json.loads(
        _policy_sub().replace("${AWS::Partition}", partition)
        .replace("${AWS::AccountId}", account).replace("${Gateway.GatewayArn}", gateway_arn)
    )
    got_policy = json.loads(control.get_resource_policy(resourceArn=gateway_arn)["policy"])
    assert got_policy == want_policy, f"GetResourcePolicy {got_policy!r}, expected {want_policy!r}"

    # Children first: an update drops the three while the gateway stays; each child's own absence.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(gateway_name, target_name, False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    live_arn = control.get_gateway(gatewayIdentifier=gateway_id)["gatewayArn"]
    assert live_arn == gateway_arn, f"gateway ARN after the update {live_arn!r} != {gateway_arn!r}"
    get_limit = lambda: control.get_gateway_rate_limit(  # noqa: E731
        gatewayIdentifier=gateway_id, rateLimitId=rate_limit_id)
    until_raises(get_limit)
    gone = ("ResourceNotFoundException", f"Rate limit not found: {rate_limit_id}")
    expect_error(get_limit, *gone)
    get_rule = lambda: control.get_gateway_rule(gatewayIdentifier=gateway_id, ruleId=rule_id)  # noqa: E731
    until_raises(get_rule)
    rule_gone = ("ResourceNotFoundException", f"GatewayRule {rule_id} not found")
    expect_error(get_rule, *rule_gone)
    # The policy's own removal: GetResourcePolicy on the live gateway answers 200 with an empty
    # body (no policy member), not a NotFound, and the removal is eventually consistent. Polled
    # (bounded) until the policy member is gone, then the body is graded as exactly empty.
    policy_after = _poll_until(lambda: control.get_resource_policy(resourceArn=gateway_arn),
                               lambda r: "policy" not in r, timeout_s=300.0, interval_s=5.0)
    body = {k: v for k, v in policy_after.items() if k != "ResponseMetadata"}
    assert body == {}, f"GetResourcePolicy after the update {body!r}"

    delete_stack(cfn, stack_id)
    get_gw = lambda: control.get_gateway(gatewayIdentifier=gateway_id)  # noqa: E731
    until_raises(get_gw)
    expect_error(get_gw, *_GATEWAY_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
