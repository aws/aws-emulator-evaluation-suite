"""cfn-lambda-env-secretsmanager-missing-json-key-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-env-secretsmanager-missing-json-key-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "secretsmanager"]

_DEPLOY_TIMEOUT_S = 900.0

_CODE = """
import os

def handler(event, context):
    return {"api_key": os.environ.get("API_KEY")}
"""


def _template(secret_arn: str, key: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
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
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                        "Timeout": 15,
                        "Code": {"ZipFile": _CODE},
                        "Environment": {
                            "Variables": {
                                "API_KEY": "{{resolve:secretsmanager:"
                                + secret_arn
                                + ":SecretString:"
                                + key
                                + "}}"
                            }
                        },
                    },
                },
            },
            "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
        }
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda env var whose {{resolve:secretsmanager:...:SecretString:key}} names a missing JSON
    key fails creation and rolls the stack back, naming the key in the failure reason; the same
    template with an existing key deploys and the function reports that key's value.
    """
    sm = ctx.client("secretsmanager")
    cfn = ctx.client("cloudformation")
    awslambda = ctx.client("lambda")

    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-xsvc-cfnenv-secret-"),
        SecretString=json.dumps({"username": "app", "api_key": "sim2real-apikey-value"}),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    bad_stack = ctx.unique_name("sim2real-xsvc-cfnenv-bad-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(secret_arn, "no_such_key"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    bad_status = _wait_stack(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a reference to a missing JSON key must roll the stack back; it ended {bad_status!r}"
    )
    failures = _failures(cfn, bad_stack)
    assert failures == [
        ("Fn", "CREATE_FAILED", "Could not find a value associated with JSONKey in SecretString")
    ], f"the function must fail on the unresolvable key and nothing else; failures were {failures!r}"

    functions = _list_function_names(awslambda)
    leaked = [n for n in functions if n.startswith(bad_stack + "-")]
    assert leaked == [], f"the rolled-back stack must leave no Lambda function behind; found {leaked!r}"

    good_stack = ctx.unique_name("sim2real-xsvc-cfnenv-ok-")
    # Registered before the stack so LIFO reaps the log group after the function is gone.
    good_fn: dict[str, str] = {}
    ctx.on_cleanup(
        lambda: _reap_lambda_log_group(ctx.client("logs"), good_fn["name"]) if good_fn else None
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(secret_arn, "api_key"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    good_status = _wait_stack(cfn, good_stack)
    assert good_status == "CREATE_COMPLETE", (
        f"the control naming an existing key must deploy; it ended {good_status!r}: "
        f"{_failures(cfn, good_stack)!r}"
    )
    fn_name = _outputs(cfn, good_stack)["FunctionName"]
    good_fn["name"] = fn_name
    payload = _invoke_json(awslambda, fn_name)
    assert payload == {"api_key": "sim2real-apikey-value"}, (
        f"the control must receive the key's value; got {payload!r}"
    )


_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _wait_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)


def _failures(cfn, stack_name):
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]


def _outputs(cfn, stack_name) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _invoke_json(awslambda, function_name: str) -> dict[str, Any]:
    response = awslambda.invoke(
        FunctionName=function_name, InvocationType="RequestResponse", Payload=b"{}"
    )
    body = response["Payload"].read().decode()
    assert not response.get("FunctionError"), f"{function_name} failed: {body}"
    return json.loads(body)


def _list_function_names(awslambda) -> list[str]:
    names: list[str] = []
    paginator = awslambda.get_paginator("list_functions")
    for page in paginator.paginate():
        names.extend(f["FunctionName"] for f in page["Functions"])
    return names


def _reap_lambda_log_group(logs, function_name: str, *, rounds: int = 6, interval_s: float = 5.0) -> None:
    """Lambda creates /aws/lambda/<fn> on first invoke and delete_function never removes it; a
    late log flush can recreate the group after a delete, so this deletes and re-checks until the
    group stays absent, and raises if it keeps reappearing."""
    log_group = f"/aws/lambda/{function_name}"
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=log_group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
        found = logs.describe_log_groups(logGroupNamePrefix=log_group).get("logGroups", [])
        if not any(g["logGroupName"] == log_group for g in found):
            return
    raise RuntimeError(f"log group {log_group} kept reappearing after delete")


def _delete_stack(cfn, stack_name, timeout_s=_DEPLOY_TIMEOUT_S):
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
