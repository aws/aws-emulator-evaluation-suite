"""cfn-lambda-env-ssm-dynamic-reference-and-parameter-type-resolve-and-update."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-env-ssm-dynamic-reference-and-parameter-type-resolve-and-update"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "ssm"]

_DEPLOY_TIMEOUT_S = 900.0

_CODE = """
import os

def handler(event, context):
    return {"dynamic": os.environ.get("DYNAMIC"), "param_type": os.environ.get("PARAM_TYPE")}
"""


def _template(dynamic_source: str, param_type_key: str, marker: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                param_type_key: {"Type": "AWS::SSM::Parameter::Value<String>"},
            },
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
                        "Description": marker,
                        "Code": {"ZipFile": _CODE},
                        "Environment": {
                            "Variables": {
                                "DYNAMIC": "{{resolve:ssm:" + dynamic_source + "}}",
                                "PARAM_TYPE": {"Ref": param_type_key},
                            }
                        },
                    },
                },
            },
            "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda Environment variable set from a versionless {{resolve:ssm:...}} reference and one
    set from Ref of an AWS::SSM::Parameter::Value<String> parameter both reach the deployed
    function, and an update touching the function re-resolves both to the changed SSM values.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    awslambda = ctx.client("lambda")

    dynamic_source = "/" + ctx.unique_name("sim2real-xsvc-cfnenv-dyn-")
    param_type_source = "/" + ctx.unique_name("sim2real-xsvc-cfnenv-pt-")
    param_type_key = "ParamTypeSource"

    ssm.put_parameter(Name=dynamic_source, Type="String", Value="dyn-v1", Tags=_TAG_LIST)
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=dynamic_source))
    ssm.put_parameter(Name=param_type_source, Type="String", Value="pt-v1", Tags=_TAG_LIST)
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_type_source))

    stack_name = ctx.unique_name("sim2real-xsvc-cfnenv-")
    # Registered before the stack so LIFO reaps the log group after the function is gone.
    stack_fn: dict[str, str] = {}
    ctx.on_cleanup(
        lambda: _reap_lambda_log_group(ctx.client("logs"), stack_fn["name"]) if stack_fn else None
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(dynamic_source, param_type_key, "sim2real marker one"),
        Capabilities=["CAPABILITY_IAM"],
        Parameters=[{"ParameterKey": param_type_key, "ParameterValue": param_type_source}],
        Tags=_TAG_LIST,
    )
    status = _wait_stack(cfn, stack_name)
    assert status == "CREATE_COMPLETE", (
        f"stack must deploy; it ended {status!r}: {_failures(cfn, stack_name)!r}"
    )
    fn_name = _outputs(cfn, stack_name)["FunctionName"]
    stack_fn["name"] = fn_name

    payload = _invoke_json(awslambda, fn_name)
    assert payload == {"dynamic": "dyn-v1", "param_type": "pt-v1"}, (
        f"both env vars must carry the resolved SSM values at create; got {payload!r}"
    )

    ssm.put_parameter(Name=dynamic_source, Type="String", Value="dyn-v2", Overwrite=True)
    ssm.put_parameter(Name=param_type_source, Type="String", Value="pt-v2", Overwrite=True)

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_template(dynamic_source, param_type_key, "sim2real marker two"),
        Capabilities=["CAPABILITY_IAM"],
        Parameters=[{"ParameterKey": param_type_key, "ParameterValue": param_type_source}],
    )
    status = _wait_stack(cfn, stack_name)
    assert status == "UPDATE_COMPLETE", (
        f"stack update must complete; it ended {status!r}: {_failures(cfn, stack_name)!r}"
    )

    payload = _invoke_json(awslambda, fn_name)
    assert payload == {"dynamic": "dyn-v2", "param_type": "pt-v2"}, (
        f"an update that touches the function must re-resolve both the dynamic reference and the "
        f"parameter-typed Ref to the new SSM values; got {payload!r}"
    )


# ===== helpers =====
_TAG_LIST = [{"Key": "sim2real:managed", "Value": "true"},
             {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"}]


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
