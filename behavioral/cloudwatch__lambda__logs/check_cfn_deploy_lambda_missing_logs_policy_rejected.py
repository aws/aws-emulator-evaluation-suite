"""cfn-deploy-lambda-missing-logs-policy-rejected."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-missing-logs-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two functions in one stack, both invoke cleanly, but only the one whose role grants
    CloudWatch Logs writes log events; the one with no policy beyond its trust document writes
    none."""
    good_fn = _xname(ctx, "goodfn")
    bad_fn = _xname(ctx, "badfn")

    code = "def handler(event, context):\n    print('hello from sim2real')\n    return {'ok': True}\n"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GoodExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "BadExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                    # deliberately: no ManagedPolicyArns, no inline Policies -> no logs:* grant
                },
            },
            "GoodFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": good_fn,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["GoodExecRole", "Arn"]},
                    "Code": {"ZipFile": code},
                    "Timeout": 30,
                },
            },
            "BadFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": bad_fn,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["BadExecRole", "Arn"]},
                    "Code": {"ZipFile": code},
                    "Timeout": 30,
                },
            },
        },
        "Outputs": {
            "GoodFunctionName": {"Value": {"Ref": "GoodFunction"}},
            "BadFunctionName": {"Value": {"Ref": "BadFunction"}},
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    good_resp = lam.invoke(FunctionName=good_fn, InvocationType="RequestResponse", Payload=b"{}")
    bad_resp = lam.invoke(FunctionName=bad_fn, InvocationType="RequestResponse", Payload=b"{}")

    # Both invocations complete successfully at the Lambda service level -- missing logs
    # permissions do not fail the invocation itself, only downstream log delivery.
    assert good_resp["StatusCode"] == 200 and "FunctionError" not in good_resp
    assert bad_resp["StatusCode"] == 200 and "FunctionError" not in bad_resp

    good_log_group = f"/aws/lambda/{good_fn}"
    bad_log_group = f"/aws/lambda/{bad_fn}"

    def _good_events():
        try:
            return logs.filter_log_events(logGroupName=good_log_group).get("events", [])
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise

    # Positive control: the properly-permissioned sibling function's logs show up. Time this on
    # the same wiring (same stack, same run) so the negative window below can be calibrated to
    # it, instead of a guessed constant.
    good_start = time.monotonic()
    good_events = _poll_until(
        _good_events,
        lambda evs: len(evs) >= 1,
        timeout_s=60,
        interval_s=3.0,
        description=f"log events for {good_fn} (positive control)",
    )
    assert len(good_events) >= 1
    good_latency_s = time.monotonic() - good_start

    def _bad_group_exists():
        try:
            resp = logs.describe_log_groups(logGroupNamePrefix=bad_log_group)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return False
            raise
        return any(g["logGroupName"] == bad_log_group for g in resp.get("logGroups", []))

    # Negative: hold absence for a window calibrated to the positive control's own observed
    # latency (>= 3x, floored at 15s so a fast positive control doesn't shrink the window to
    # nothing), re-checking on a bounded retry rather than trusting a single point-in-time read
    # after a blind sleep. Two independent observables: log-group existence and event count.
    negative_window_s = max(15.0, good_latency_s * 3)
    deadline = time.monotonic() + negative_window_s
    while True:
        if _bad_group_exists():
            bad_events = logs.filter_log_events(logGroupName=bad_log_group).get("events", [])
            assert len(bad_events) == 0, (
                f"expected no log events for permission-less function, got {bad_events}"
            )
        # else: log group was never created at all, which is the strongest form of the negative.
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
