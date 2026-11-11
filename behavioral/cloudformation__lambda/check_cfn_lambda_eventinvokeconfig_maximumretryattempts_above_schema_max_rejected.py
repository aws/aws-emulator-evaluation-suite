"""cfn-lambda-eventinvokeconfig-maximumretryattempts-above-schema-max-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-eventinvokeconfig-maximumretryattempts-above-schema-max-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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


def _template(function_name: str, retries: int) -> str:
    """A role, a function and its $LATEST EventInvokeConfig retrying ``retries`` times."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": function_name, "Runtime": "python3.12", "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]}, "Code": {"ZipFile": _SRC}}},
            "Eic": {"Type": "AWS::Lambda::EventInvokeConfig", "Properties": {
                "FunctionName": {"Ref": "Fn"}, "Qualifier": "$LATEST",
                "MaximumRetryAttempts": retries}},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::Lambda::EventInvokeConfig with MaximumRetryAttempts 3, above the schema maximum of 2,
    fails validation with the exact path and reason before the stack creates its function; the
    same template with 2 deploys and GetFunctionEventInvokeConfig reads back 2.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    stack = ctx.unique_name("sim2real-cfres-eicbadretry-")
    function_name = ctx.unique_name("sim2real-cfres-eicbadretry-fn-")

    stack_id = create_stack(ctx, cfn, stack, _template(function_name, 3),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, stack ended in {status!r}"
    partition = stack_id.split(":")[1]

    got = [(row[0], row[5], row[4]) for row in validation_rows(cfn, stack_id)]
    want = [("Eic", "/Resources/Eic/Properties/MaximumRetryAttempts",
             "#/MaximumRetryAttempts: 3 is not less or equal to 2")]
    assert got == want, f"VALIDATION_ERROR events: expected {want!r}, got {got!r}"

    # Property validation runs before any resource creation: the stack never created its function.
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    assert resources == [], f"expected no stack resources ever created, got {resources!r}"
    expected_arn = f"arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    fn_absent = ("ResourceNotFoundException", f"Function not found: {expected_arn}")
    expect_error(lambda: lam.get_function(FunctionName=function_name), *fn_absent)

    # Positive control: the identical template with the schema maximum deploys and reads back.
    good_stack = ctx.unique_name("sim2real-cfres-eicgoodretry-")
    good_function = ctx.unique_name("sim2real-cfres-eicgoodretry-fn-")
    good_id = create_stack(ctx, cfn, good_stack, _template(good_function, 2),
                           Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack: expected CREATE_COMPLETE, got {status!r}: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    eic = lam.get_function_event_invoke_config(FunctionName=good_function, Qualifier="$LATEST")
    good_arn = f"arn:{partition}:lambda:{ctx.region}:{ctx.account}:function:{good_function}:$LATEST"
    got_eic = (eic["FunctionArn"], eic["MaximumRetryAttempts"])
    assert got_eic == (good_arn, 2), (
        f"control GetFunctionEventInvokeConfig (FunctionArn, MaximumRetryAttempts): {got_eic!r}, "
        f"expected {(good_arn, 2)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
