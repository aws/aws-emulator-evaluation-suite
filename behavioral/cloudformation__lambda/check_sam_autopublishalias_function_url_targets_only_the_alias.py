"""sam-autopublishalias-function-url-targets-only-the-alias."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-autopublishalias-function-url-targets-only-the-alias"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


def _template(fn_name: str) -> dict:
    """A SAM function with AutoPublishAlias live and an AWS_IAM function URL."""
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Fn": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                    "AutoPublishAlias": "live",
                    "InlineCode": (
                        "def handler(event, context):\n"
                        "    return {'statusCode': 200, 'body': 'ok'}\n"
                    ),
                    "FunctionUrlConfig": {"AuthType": "AWS_IAM"},
                },
            },
        },
        "Outputs": {"FunctionUrl": {"Value": {"Fn::GetAtt": ["FnUrl", "FunctionUrl"]}}},
    }


def _refusal(fn):
    """Call fn(); return its (code, message). An unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); raises at the deadline naming the last observation."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack_status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _stack_failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; any other end raises."""
    status = _stack_status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _poll(lambda: _stack_status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
              timeout_s=_DEADLINE_S, interval_s=3.0, what=f"stack {stack_id} settled")
    if _stack_status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack_status(cfn, stack_id),
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=3.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_stack_failures(cfn, stack_id)!r}")


def _deploy(ctx, cfn, stack: str, template: dict) -> str:
    """Create the stack through a change set and wait for CREATE_COMPLETE; cleanup registered first."""
    change_set = ctx.unique_name("sim2real-sam-ffa-cs-")
    created = cfn.create_change_set(
        StackName=stack, ChangeSetName=change_set, ChangeSetType="CREATE",
        TemplateBody=json.dumps(template), Capabilities=_CAPS,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))

    cs_status = _poll(
        lambda: cfn.describe_change_set(ChangeSetName=change_set, StackName=stack_id)["Status"],
        lambda s: s in ("CREATE_COMPLETE", "FAILED"),
        timeout_s=120.0, interval_s=3.0, what=f"change set {change_set} created",
    )
    assert cs_status == "CREATE_COMPLETE", (
        f"change set {change_set} ended {cs_status}: "
        f"{cfn.describe_change_set(ChangeSetName=change_set, StackName=stack_id).get('StatusReason')!r}"
    )
    cfn.execute_change_set(ChangeSetName=change_set, StackName=stack_id)
    final = _poll(lambda: _stack_status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                  timeout_s=_DEADLINE_S, interval_s=3.0, what=f"stack {stack_id} created")
    assert final == "CREATE_COMPLETE", (
        f"stack {stack_id} ended {final}: {_stack_failures(cfn, stack_id)!r}")
    return stack_id


def _outputs(cfn, stack_id: str) -> dict:
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])}


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A SAM function's AWS_IAM function URL, deployed with AutoPublishAlias live, reports the
    stack's own output URL at Qualifier=live and targets the alias's own ARN; the function's
    unqualified ($LATEST) config does not exist, and the stack's delete removes it entirely.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-functionurlconfig.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    fn = ctx.unique_name("sim2real-sam-ffa-")
    stack = ctx.unique_name("sim2real-sam-ffa-")

    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    stack_id = _deploy(ctx, cfn, stack, _template(fn))

    published_url = _outputs(cfn, stack_id)["FunctionUrl"]
    alias = lam.get_alias(FunctionName=fn, Name="live")

    qualified = lam.get_function_url_config(FunctionName=fn, Qualifier="live")
    assert (qualified["FunctionUrl"], qualified["AuthType"], qualified["FunctionArn"]) == (
        published_url, "AWS_IAM", alias["AliasArn"]
    ), (
        f"GetFunctionUrlConfig(Qualifier=live) must match the stack's own output and target the "
        f"live alias's own ARN; got {qualified!r}, output {published_url!r}, alias {alias!r}"
    )

    code, message = _refusal(lambda: lam.get_function_url_config(FunctionName=fn))
    assert code == "ResourceNotFoundException", (
        f"GetFunctionUrlConfig with no Qualifier must be refused once the URL config exists only "
        f"on the live alias and not on $LATEST; got {code!r}"
    )
    assert message == "The resource you requested does not exist.", message

    _delete_stack(cfn, stack_id)
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    gone = _refusal(lambda: lam.get_function(FunctionName=fn))
    assert gone == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"GetFunction after the stack delete must name the function's own ARN; got {gone!r}"
    )
    gone_url = _refusal(lambda: lam.get_function_url_config(FunctionName=fn, Qualifier="live"))
    assert gone_url == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"GetFunctionUrlConfig(Qualifier=live) after the stack delete: {gone_url!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
