"""deploy-resource-policy-mismatched-arn-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-resource-policy-mismatched-arn-rejected-and-rolled-back"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

_REJECTED = (
    "Policy statement block must contain exactly one resource ARN that matches the provided "
    "resource ARN (Service: Bedrock AgentCore Control; Operation: PutResourcePolicy; Status Code: "
    "400; Error Code: ValidationException; Request ID: <id>)",
    "InvalidRequest",
)
_GATEWAY_GONE = (
    "ResourceNotFoundException",
    "Failed to retrieve gateway because it doesn't exist. "
    "Retry the request with a different resource identifier.",
)
_POLICY_GONE = ("ResourceNotFoundException", "ResourceArn provided in the request does not exist")
_MATCHING = "${Gateway.GatewayArn}"
# Every gateway of the account and region, not this one's own ARN: the one bad value.
_MISMATCHED = "arn:${AWS::Partition}:bedrock-agentcore:${AWS::Region}:${AWS::AccountId}:gateway/*"


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "-")


def _policy(resource):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "Sim2RealGatewayInvoke",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"},
            "Action": "bedrock-agentcore:InvokeGateway",
            "Resource": resource,
        }],
    })


def _template(gateway_name, resource):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GatewayRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }]},
            }},
            "Gateway": {"Type": "AWS::BedrockAgentCore::Gateway", "Properties": {
                "Name": gateway_name, "RoleArn": {"Fn::GetAtt": ["GatewayRole", "Arn"]},
                "AuthorizerType": "AWS_IAM",
            }},
            "GatewayResourcePolicy": {"Type": "AWS::BedrockAgentCore::ResourcePolicy",
                                      "Properties": {
                                          "ResourceArn": {"Fn::GetAtt": ["Gateway", "GatewayArn"]},
                                          "Policy": {"Fn::Sub": _policy(resource)},
                                      }},
        },
        "Outputs": {"GatewayArn": {"Value": {"Fn::GetAtt": ["Gateway", "GatewayArn"]}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ResourcePolicy naming every gateway instead of its own ResourceArn is refused and rolled back.

    The handler's exact mismatch reason is graded and AgentCore no longer has the gateway, while
    the same template naming the gateway's own ARN deploys and stores the policy.
    """
    control = ctx.client("bedrock-agentcore-control")
    cfn = ctx.client("cloudformation")
    good_name = _alnum_name(ctx, "sim2realcfnrpgoodgw")
    bad_name = _alnum_name(ctx, "sim2realcfnrpbadgw")

    # Positive control: the same template, the statement's Resource the gateway's own ARN.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-respolicy-good-"),
                           _template(good_name, _MATCHING), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    good_arn = stack_outputs(cfn, good_id)["GatewayArn"]
    partition, account = good_id.split(":")[1], good_id.split(":")[4]
    want_policy = json.loads(
        _policy(good_arn).replace("${AWS::Partition}", partition)
        .replace("${AWS::AccountId}", account)
    )
    got_policy = json.loads(control.get_resource_policy(resourceArn=good_arn)["policy"])
    assert got_policy == want_policy, f"control policy {got_policy!r}, expected {want_policy!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-respolicy-bad-"),
                          _template(bad_name, _MISMATCHED), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"mismatched-ARN stack ended {status!r}"
    events = stack_events(cfn, bad_id)
    got = handler_reason(failed_reason(events, "GatewayResourcePolicy"), ctx.account, bad_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through AgentCore, before this check deletes anything: the gateway the
    # rollback removed (id from its CREATE_COMPLETE row) and no gateway by its name.
    created = [e["PhysicalResourceId"] for e in events
               if e["LogicalResourceId"] == "Gateway" and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert len(created) == 1, f"Gateway CREATE_COMPLETE rows: {created!r}"
    bad_gateway_id = created[0]
    bad_arn = f"arn:{partition}:bedrock-agentcore:{ctx.region}:{account}:gateway/{bad_gateway_id}"
    names = [g["name"] for g in paginate(control, "list_gateways", "items")]
    assert good_name in names and bad_name not in names, (
        f"ListGateways: control {good_name!r} listed {good_name in names}, rolled-back "
        f"{bad_name!r} listed {bad_name in names}"
    )
    expect_error(lambda: control.get_gateway(gatewayIdentifier=bad_gateway_id), *_GATEWAY_GONE)
    expect_error(lambda: control.get_resource_policy(resourceArn=bad_arn), *_POLICY_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
