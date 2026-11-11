"""deploy-cfn-iam-role-trust-events-service-cloudfront-target."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-iam-role-trust-events-service-cloudfront-target"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]

_LAMBDA_CODE = (
    "import boto3\n"
    "\n"
    "def handler(event, context):\n"
    "    client = boto3.client('cloudfront')\n"
    "    resp = client.list_distributions()\n"
    "    return {'distributionQuantity': resp['DistributionList']['Quantity']}\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed role's trust policy holds exactly one Allow sts:AssumeRole statement for events.amazonaws.com,
    and through it a matching event starts a Step Functions execution that SUCCEEDS with the integer distribution
    count a Lambda read from cloudfront:ListDistributions."""
    template = json.dumps(_build_template())
    result = _deploy_cfn(ctx, template)
    role_name = result["outputs"]["RoleName"]
    role_arn = result["outputs"]["RoleArn"]
    state_machine_arn = result["outputs"]["StateMachineArn"]
    rule_name = result["outputs"]["RuleName"]

    iam = ctx.client("iam")
    trust_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    statements = trust_doc["Statement"]
    assert len(statements) == 1, f"expected exactly one trust statement, got {statements!r}"
    stmt = statements[0]
    assert stmt["Effect"] == "Allow", f"expected Allow, got {stmt['Effect']!r}"
    assert stmt["Action"] == "sts:AssumeRole", f"expected sts:AssumeRole, got {stmt['Action']!r}"
    principal = stmt["Principal"]["Service"]
    principal_set = {principal} if isinstance(principal, str) else set(principal)
    assert principal_set == {"events.amazonaws.com"}, (
        f"expected trust principal {{'events.amazonaws.com'}}, got {principal_set!r}"
    )

    events = ctx.client("events")
    events.describe_rule(Name=rule_name)  # rule genuinely exists

    sfn = ctx.client("stepfunctions")
    before = {
        e["executionArn"]
        for e in sfn.list_executions(stateMachineArn=state_machine_arn)["executions"]
    }

    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfronttest",
                "DetailType": "cf-mgmt-trigger",
                "Detail": json.dumps({"trigger": ctx.unique_name("sim2real-trigger-")}),
            }
        ]
    )

    def _new_execution():
        current = sfn.list_executions(stateMachineArn=state_machine_arn)["executions"]
        fresh = [e for e in current if e["executionArn"] not in before]
        return fresh[0] if fresh else None

    started = _poll_until(
        _new_execution,
        lambda ex: ex is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="EventBridge rule started a new Step Functions execution via the trusted role",
    )

    def _terminal():
        return sfn.describe_execution(executionArn=started["executionArn"])

    final = _poll_until(
        _terminal,
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0,
        interval_s=3.0,
        description="Step Functions execution reaches a terminal state",
    )
    assert final["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED, got {final['status']!r}: {final.get('error')}/{final.get('cause')}"
    )
    output = json.loads(final["output"])
    assert isinstance(output["distributionQuantity"], int), (
        f"expected the Lambda's real cloudfront:ListDistributions call to report an int "
        f"Quantity, got {output['distributionQuantity']!r}"
    )
    assert role_arn.endswith(f":role/{role_name}"), (
        f"stack Outputs RoleArn {role_arn!r} does not reference RoleName {role_name!r}"
    )


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _build_template() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaExecRole": {
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
                    "Policies": [
                        {
                            "PolicyName": "cf-list",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "cloudfront:ListDistributions",
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "CFTestFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Code": {"ZipFile": _LAMBDA_CODE},
                },
            },
            "SfnExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "states.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "invoke-lambda",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "lambda:InvokeFunction",
                                        "Resource": {"Fn::GetAtt": ["CFTestFunction", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "TestStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "RoleArn": {"Fn::GetAtt": ["SfnExecRole", "Arn"]},
                    "DefinitionString": {
                        "Fn::Sub": (
                            '{"Comment":"sim2real","StartAt":"InvokeLambda",'
                            '"States":{"InvokeLambda":{"Type":"Task",'
                            '"Resource":"${CFTestFunction.Arn}","End":true}}}'
                        )
                    },
                },
            },
            "EventsInvokeRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "start-execution",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "states:StartExecution",
                                        "Resource": {"Ref": "TestStateMachine"},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "TestRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["sim2real.cloudfronttest"],
                        "detail-type": ["cf-mgmt-trigger"],
                    },
                    "Targets": [
                        {
                            "Id": "sfn-target",
                            "Arn": {"Ref": "TestStateMachine"},
                            "RoleArn": {"Fn::GetAtt": ["EventsInvokeRole", "Arn"]},
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["EventsInvokeRole", "Arn"]}},
            "RoleName": {"Value": {"Ref": "EventsInvokeRole"}},
            "StateMachineArn": {"Value": {"Ref": "TestStateMachine"}},
            "RuleName": {"Value": {"Ref": "TestRule"}},
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
