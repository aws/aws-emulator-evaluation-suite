"""cfn-lambda-env-ssm-missing-dynamic-reference-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-env-ssm-missing-dynamic-reference-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "ssm"]

_DEPLOY_TIMEOUT_S = 900.0

_CODE = """
import os

def handler(event, context):
    return {"dynamic": os.environ.get("DYNAMIC")}
"""


def _template(source: str) -> str:
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
                            "Variables": {"DYNAMIC": "{{resolve:ssm:" + source + "}}"}
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
    """A {{resolve:ssm:...}} reference to a missing SSM parameter rolls the stack back before any
    resource is provisioned, with the stack's own event naming the parameter; the same template
    naming an existing parameter deploys and the function reports its value.
    """
    ssm = ctx.client("ssm")
    cfn = ctx.client("cloudformation")
    awslambda = ctx.client("lambda")

    missing_source = "/" + ctx.unique_name("sim2real-xsvc-cfnenv-missing-")
    bad_stack = ctx.unique_name("sim2real-xsvc-cfnenv-bad-")
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(missing_source),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAG_LIST,
    )
    bad_status = _wait_stack(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a dynamic reference to an SSM parameter that does not exist must roll the stack back; "
        f"it ended {bad_status!r}"
    )
    # CloudFormation resolves every dynamic reference in the template BEFORE it touches any
    # resource, so the failure lands on the stack's own event, naming the missing parameter --
    # not on "Fn" or "Role", neither of which is ever provisioned.
    events = cfn.describe_stack_events(StackName=bad_stack)["StackEvents"]
    stack_reasons = [
        e["ResourceStatusReason"]
        for e in events
        if e["LogicalResourceId"] == bad_stack
        and e["ResourceStatus"] == "CREATE_IN_PROGRESS"
        and e.get("ResourceStatusReason") not in (None, "User Initiated")
    ]
    assert stack_reasons == [f"Parameters: [ssm:{missing_source}] cannot be found."], (
        f"the stack's own event must name the missing parameter; reasons were {stack_reasons!r}"
    )
    resource_events = [
        e["LogicalResourceId"] for e in events if e["ResourceType"] != "AWS::CloudFormation::Stack"
    ]
    assert resource_events == [], (
        f"dynamic-reference resolution must fail before any resource is touched; saw events for "
        f"{resource_events!r}"
    )
    code, message = _ssm_error(ssm, missing_source)
    assert code == "ParameterNotFound", (
        f"the parameter named in the rollback must genuinely not exist; GetParameter gave {code!r}"
    )
    assert message == "", f"unexpected GetParameter not-found message: {message!r}"
    functions = _list_function_names(awslambda)
    leaked = [n for n in functions if n.startswith(bad_stack + "-")]
    assert leaked == [], f"the rolled-back stack must leave no Lambda function behind; found {leaked!r}"

    good_source = "/" + ctx.unique_name("sim2real-xsvc-cfnenv-good-")
    ssm.put_parameter(Name=good_source, Type="String", Value="present-value", Tags=_TAG_LIST)
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=good_source))
    good_stack = ctx.unique_name("sim2real-xsvc-cfnenv-ok-")
    # Registered before the stack so LIFO reaps the log group after the function is gone.
    good_fn: dict[str, str] = {}
    ctx.on_cleanup(
        lambda: _reap_lambda_log_group(ctx.client("logs"), good_fn["name"]) if good_fn else None
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_source),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAG_LIST,
    )
    good_status = _wait_stack(cfn, good_stack)
    assert good_status == "CREATE_COMPLETE", (
        f"the control naming an existing parameter must deploy; it ended {good_status!r}: "
        f"{_failures(cfn, good_stack)!r}"
    )
    fn_name = _outputs(cfn, good_stack)["FunctionName"]
    good_fn["name"] = fn_name
    payload = _invoke_json(awslambda, fn_name)
    assert payload == {"dynamic": "present-value"}, (
        f"the control must receive the parameter's value; got {payload!r}"
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


def _ssm_error(ssm, name: str) -> tuple[str, str]:
    try:
        ssm.get_parameter(Name=name)
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected GetParameter({name!r}) to be refused, but it succeeded")


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
