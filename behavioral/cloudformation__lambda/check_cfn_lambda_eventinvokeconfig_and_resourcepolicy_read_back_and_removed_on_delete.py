"""cfn-lambda-eventinvokeconfig-and-resourcepolicy-read-back-and-removed-on-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-eventinvokeconfig-and-resourcepolicy-read-back-and-removed-on-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

_SRC = "def handler(event, context):\n    return {'ok': True}\n"
_POLICY_SID = "sim2real-resource-policy"


def _template(tok: str) -> str:
    resource_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:lambda:${{AWS::Region}}:${{AWS::AccountId}}"
                               f":function:{tok}"}
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": _POLICY_SID,
            "Effect": "Allow",
            "Principal": {"AWS": {"Ref": "AWS::AccountId"}},
            "Action": "lambda:GetFunction",
            "Resource": resource_arn,
        }],
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": tok, "Runtime": "python3.12", "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]}, "Code": {"ZipFile": _SRC}}},
            "Eic": {"Type": "AWS::Lambda::EventInvokeConfig", "Properties": {
                "FunctionName": {"Ref": "Fn"}, "Qualifier": "$LATEST", "MaximumRetryAttempts": 0}},
            "Rp": {"Type": "AWS::Lambda::ResourcePolicy", "Properties": {
                "ResourceArn": {"Fn::GetAtt": ["Fn", "Arn"]}, "PolicyDocument": policy_document}},
        },
        "Outputs": {
            "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}},
            "EicRef": {"Value": {"Ref": "Eic"}},
            "RpRef": {"Value": {"Ref": "Rp"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deployed EventInvokeConfig's Ref and settings agree with GetFunctionEventInvokeConfig, and
    a sibling ResourcePolicy's statement reads back through GetResourcePolicy and GetPolicy; after
    the stack delete the function and both answer ResourceNotFoundException.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfres-eicrp-")
    stack = ctx.unique_name("sim2real-cfres-eicrpstk-")

    stack_id = create_stack(ctx, cfn, stack, _template(name), Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, stack ended in {status!r}: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]

    outputs = stack_outputs(cfn, stack_id)
    fn_arn = outputs["FnArn"]
    assert outputs["EicRef"] == f"{name}|$LATEST", (
        f"Ref of the EventInvokeConfig is {outputs['EicRef']!r}, expected {name}|$LATEST")
    assert outputs["RpRef"] == fn_arn, f"Ref of the ResourcePolicy is {outputs['RpRef']!r}, expected {fn_arn!r}"

    eic = lam.get_function_event_invoke_config(FunctionName=name, Qualifier="$LATEST")
    assert eic["FunctionArn"] == f"{fn_arn}:$LATEST", (
        f"GetFunctionEventInvokeConfig FunctionArn is {eic['FunctionArn']!r}, expected {fn_arn}:$LATEST")
    assert eic["MaximumRetryAttempts"] == 0, (
        f"GetFunctionEventInvokeConfig MaximumRetryAttempts is {eic['MaximumRetryAttempts']!r}, expected 0")

    rp_policy = json.loads(lam.get_resource_policy(ResourceArn=fn_arn)["Policy"])
    rp_statements = {s["Sid"]: s for s in rp_policy["Statement"]}
    assert _POLICY_SID in rp_statements, (
        f"statement {_POLICY_SID!r} not found in GetResourcePolicy's statements {sorted(rp_statements)!r}")
    rp_stmt = rp_statements[_POLICY_SID]
    assert (rp_stmt["Effect"], rp_stmt["Action"]) == ("Allow", "lambda:GetFunction"), (
        f"unexpected Effect/Action {rp_stmt['Effect']!r} {rp_stmt['Action']!r}")
    assert rp_stmt["Principal"] == {"AWS": f"arn:{partition}:iam::{ctx.account}:root"}, (
        f"unexpected Principal {rp_stmt['Principal']!r}")
    want_fn_arn = f"arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:{name}"
    assert fn_arn == want_fn_arn, f"GetAtt Fn.Arn {fn_arn!r}, expected {want_fn_arn!r}"
    conf = lam.get_function_configuration(FunctionName=name)
    got_conf = (conf["FunctionArn"], conf["Runtime"], conf["Handler"], conf["Role"])
    want_conf = (fn_arn, "python3.12", "index.handler", outputs["RoleArn"])
    assert got_conf == want_conf, (
        f"GetFunctionConfiguration (FunctionArn, Runtime, Handler, Role) {got_conf!r}, expected "
        f"{want_conf!r}")
    assert rp_stmt["Resource"] == fn_arn, f"statement Resource {rp_stmt['Resource']!r}, expected {fn_arn!r}"

    get_policy = json.loads(lam.get_policy(FunctionName=name)["Policy"])
    get_policy_statements = {s["Sid"]: s for s in get_policy["Statement"]}
    assert _POLICY_SID in get_policy_statements, (
        f"statement {_POLICY_SID!r} not found in GetPolicy's statements {sorted(get_policy_statements)!r}")
    assert get_policy_statements[_POLICY_SID] == rp_stmt, (
        f"GetPolicy statement {get_policy_statements[_POLICY_SID]!r} differs from GetResourcePolicy "
        f"statement {rp_stmt!r}")

    # Delete the stack in-band; the function, its event-invoke config and its resource policy are
    # all actually gone, confirmed through Lambda's own API rather than through the stack's resource list.
    delete_stack(cfn, stack_id)

    eic_gone = ("ResourceNotFoundException",
                f"The function {fn_arn}:$LATEST doesn't have an EventInvokeConfig")
    expect_error(lambda: lam.get_function_event_invoke_config(FunctionName=name, Qualifier="$LATEST"),
                 *eic_gone)
    rp_gone = ("ResourceNotFoundException", "The resource you requested does not exist.")
    expect_error(lambda: lam.get_resource_policy(ResourceArn=fn_arn), *rp_gone)
    fn_gone = ("ResourceNotFoundException", f"Function not found: {fn_arn}")
    expect_error(lambda: lam.get_function(FunctionName=name), *fn_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
