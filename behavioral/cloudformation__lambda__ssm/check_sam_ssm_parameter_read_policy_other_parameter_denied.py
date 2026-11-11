"""sam-ssm-parameter-read-policy-other-parameter-denied."""

from __future__ import annotations

import json
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-ssm-parameter-read-policy-other-parameter-denied"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_ssm_read_policy"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """The SSMParameterReadPolicy template grants exactly the named parameter: the function reads it,
    and a read of a sibling parameter is refused with the exact AccessDeniedException.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-policy-template-list.html#ssm-parameter-read-policy
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    ssm = ctx.client("ssm")
    fn = ctx.unique_name("sim2real-sam-ssmpol-")
    stack = ctx.unique_name("sim2real-sam-ssmpol-")
    allowed = ctx.unique_name("sim2real-sam-ssmpol-allowed-")
    other = ctx.unique_name("sim2real-sam-ssmpol-other-")
    values = {allowed: ctx.unique_name("v-"), other: ctx.unique_name("v-")}
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    for name, value in values.items():
        ssm.put_parameter(Name=name, Value=value, Type="String",
                          Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(_teardown(lambda n=name: ssm.delete_parameter(Name=n), "ParameterNotFound"))
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    stack_id = _create_stack(ctx, cfn, stack, body, {"FunctionName": fn, "AllowedParameter": allowed})

    policies = _processed(cfn, stack_id)["Resources"]["FnRole"]["Properties"]["Policies"]
    statements = [p["PolicyDocument"]["Statement"] for p in policies]
    assert statements == [[
        {"Action": ["ssm:DescribeParameters"], "Effect": "Allow", "Resource": "*"},
        {"Action": ["ssm:GetParameters", "ssm:GetParameter", "ssm:GetParametersByPath"],
         "Effect": "Allow", "Resource": {"Fn::Sub": [
             "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/${parameterName}",
             {"parameterName": {"Ref": "AllowedParameter"}}]}},
    ]], f"the policy template must expand to its documented statements; got {statements!r}"

    # The generated role's grant takes effect a few seconds after the create.
    seen = _poll(lambda: _invoke(lam, fn, {"name": allowed}), lambda r: "value" in r,
                 timeout_s=90.0, interval_s=3.0, what="the function reading the granted parameter")
    assert seen == {"value": values[allowed]}, f"the granted read returned {seen!r}"

    role_arn = lam.get_function_configuration(FunctionName=fn)["Role"]
    partition, role = role_arn.split(":")[1], role_arn.rsplit("/", 1)[-1]
    denied = _invoke(lam, fn, {"name": other})
    assert denied == {
        "code": "AccessDeniedException",
        "message": (f"User: arn:{partition}:sts::{ctx.account}:assumed-role/{role}/{fn} is not "
                    f"authorized to perform: ssm:GetParameter on resource: arn:{partition}:ssm:"
                    f"{ctx.region}:{ctx.account}:parameter/{other} because no identity-based "
                    "policy allows the ssm:GetParameter action"),
    }, f"a read outside the granted parameter must be refused exactly; got {denied!r}"
    assert ssm.get_parameter(Name=other)["Parameter"]["Value"] == values[other], (
        "the refused parameter must be unchanged")


def _invoke(lam, fn: str, payload: dict) -> dict:
    """Decoded payload of a synchronous invoke that must not raise."""
    out = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
    body = out["Payload"].read().decode()
    assert "FunctionError" not in out, f"{fn} raised: {body[:300]!r}"
    return json.loads(body)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _processed(cfn, stack_id: str) -> dict:
    body = cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    return body if isinstance(body, dict) else json.loads(body)


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _create_stack(ctx, cfn, name: str, body: str, params: dict) -> str:
    """Create the stack with its delete registered at once; assert CREATE_COMPLETE."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Capabilities=_CAPS,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {name} ended {status}: {_failures(cfn, stack_id)!r}"
    return stack_id


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 1.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads, ``interval_s`` apart, find it
    absent; a late log flush that re-creates the group is deleted again."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
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
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
