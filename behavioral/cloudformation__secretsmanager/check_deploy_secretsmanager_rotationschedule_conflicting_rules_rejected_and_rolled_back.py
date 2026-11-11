"""deploy-secretsmanager-rotationschedule-conflicting-rules-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-secretsmanager-rotationschedule-conflicting-rules-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager"]

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
    "You cannot specify both rotation frequency and schedule expression together. "
    "(Service: SecretsManager, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
_BAD_RULES = {"AutomaticallyAfterDays": 30, "ScheduleExpression": "rate(10 days)"}
_GOOD_RULES = {"AutomaticallyAfterDays": 30}

_LAMBDA_SRC = """def lambda_handler(event, context):
    return
"""


def _template(secret_name: str, rules: dict) -> str:
    """A secret, a real rotation function with its invoke permission, and the schedule."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            # No policy: the function never writes logs, so it leaves no log group behind.
            "RotationRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "RotationFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.lambda_handler",
                    "Role": {"Fn::GetAtt": ["RotationRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": _LAMBDA_SRC},
                },
            },
            "InvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "Action": "lambda:InvokeFunction",
                    "FunctionName": {"Fn::GetAtt": ["RotationFunction", "Arn"]},
                    "Principal": "secretsmanager.amazonaws.com",
                    "SourceAccount": {"Ref": "AWS::AccountId"},
                },
            },
            "Secret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {"Name": secret_name, "GenerateSecretString": {}},
            },
            "RotationSchedule": {
                "Type": "AWS::SecretsManager::RotationSchedule",
                "DependsOn": "InvokePermission",
                "Properties": {
                    "SecretId": {"Ref": "Secret"},
                    "RotationLambdaARN": {"Fn::GetAtt": ["RotationFunction", "Arn"]},
                    "RotationRules": rules,
                    "RotateImmediatelyOnUpdate": False,
                },
            },
        },
        "Outputs": {
            "SecretArn": {"Value": {"Ref": "Secret"}},
            "FunctionArn": {"Value": {"Fn::GetAtt": ["RotationFunction", "Arn"]}},
            "ScheduleRef": {"Value": {"Ref": "RotationSchedule"}},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN RotationSchedule setting both AutomaticallyAfterDays and ScheduleExpression is refused
    with SecretsManager's exact message and rolls back, deleting the secret; the same template with
    AutomaticallyAfterDays alone deploys and enables rotation with that rule.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-rotationschedule.html
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    bad_secret_name = ctx.unique_name("sim2real-behav-cfn-smrot-bad-")
    bad_stack = ctx.unique_name("sim2real-behav-cfn-smrot-bad-")

    stack_id = create_stack(ctx, cf, bad_stack, _template(bad_secret_name, _BAD_RULES),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    reason = handler_reason(failed_reason(stack_events(cf, stack_id), "RotationSchedule"),
                            ctx.account, bad_secret_name)
    assert reason == _REJECTED, (
        f"expected the RotationSchedule failure reason {_REJECTED!r}, got {reason!r}"
    )

    secrets = [
        r["PhysicalResourceId"]
        for r in cf.describe_stack_resources(StackName=stack_id)["StackResources"]
        if r["ResourceType"] == "AWS::SecretsManager::Secret"
    ]
    assert len(secrets) == 1, f"expected exactly one Secret resource, got {secrets!r}"
    # The rollback itself removed the secret, before this check deletes the stack.
    expect_error(lambda: sm.describe_secret(SecretId=secrets[0]), *_NOT_FOUND)
    delete_stack(cf, stack_id)

    # ---- Positive control: the same template with one valid rotation rule. ----
    good_secret_name = ctx.unique_name("sim2real-behav-cfn-smrot-good-")
    good_stack = ctx.unique_name("sim2real-behav-cfn-smrot-good-")
    good_stack_id = create_stack(ctx, cf, good_stack, _template(good_secret_name, _GOOD_RULES),
                                 Capabilities=["CAPABILITY_IAM"])
    good_status = wait_stack(cf, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {good_status!r}: "
        f"{decisive_rows(stack_events(cf, good_stack_id))!r}"
    )

    out = stack_outputs(cf, good_stack_id)
    listed = [s for s in paginate(sm, "list_secrets", "SecretList",
                                  Filters=[{"Key": "name", "Values": [good_secret_name]}])
              if s["Name"] == good_secret_name]
    assert [s["ARN"] for s in listed] == [out["SecretArn"]], (
        f"ListSecrets by name returned {listed!r}, expected the Secret's Ref"
    )
    assert out["ScheduleRef"] == out["SecretArn"], (
        f"the RotationSchedule Ref was {out['ScheduleRef']!r}, expected the secret ARN"
    )
    described = sm.describe_secret(SecretId=out["SecretArn"])
    assert described["Name"] == good_secret_name, (
        f"expected the control secret's Name {good_secret_name!r}, got {described.get('Name')!r}"
    )
    assert described.get("RotationEnabled") is True, (
        f"RotationEnabled after the schedule deployed was {described.get('RotationEnabled')!r}"
    )
    assert described.get("RotationLambdaARN") == out["FunctionArn"], (
        f"RotationLambdaARN was {described.get('RotationLambdaARN')!r}, expected the function ARN"
    )
    assert described["RotationRules"]["AutomaticallyAfterDays"] == 30, (
        f"RotationRules were {described['RotationRules']!r}, expected AutomaticallyAfterDays 30"
    )

    delete_stack(cf, good_stack_id)
    expect_error(lambda: sm.describe_secret(SecretId=out["SecretArn"]), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
