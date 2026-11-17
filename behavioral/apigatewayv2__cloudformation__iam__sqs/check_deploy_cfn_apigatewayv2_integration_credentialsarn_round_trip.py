"""deploy-cfn-apigatewayv2-integration-credentialsarn-round-trip."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-apigatewayv2-integration-credentialsarn-round-trip"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation", "iam", "sqs"]

_CREATE_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
    }
)
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})


def _template(api_name: str, role_name: str, queue_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": queue_name},
                },
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "apigateway.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "send-message",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "sqs:SendMessage",
                                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Api": {
                    "Type": "AWS::ApiGatewayV2::Api",
                    "Properties": {"Name": api_name, "ProtocolType": "HTTP"},
                },
                "Integration": {
                    "Type": "AWS::ApiGatewayV2::Integration",
                    "Properties": {
                        "ApiId": {"Ref": "Api"},
                        "IntegrationType": "AWS_PROXY",
                        "IntegrationSubtype": "SQS-SendMessage",
                        "PayloadFormatVersion": "1.0",
                        "CredentialsArn": {"Fn::GetAtt": ["Role", "Arn"]},
                        "RequestParameters": {
                            "QueueUrl": {"Ref": "Queue"},
                            "MessageBody": "$request.body.msg",
                        },
                    },
                },
            },
            "Outputs": {
                "ApiId": {"Value": {"Ref": "Api"}},
                "IntegrationId": {"Value": {"Ref": "Integration"}},
                "RoleRef": {"Value": {"Ref": "Role"}},
                "RoleArnAttr": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            },
        }
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _stack_status(cfn, stack_id: str) -> str:
    """The stack's status read by StackId; the exact not-found pair reads as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack_id} does not exist",
        ):
            return "DELETE_COMPLETE"
        raise


def _wait_stack(ctx, cfn, stack_id: str, terminal, timeout_s: float) -> str:
    """Poll the stack by StackId until its status is in ``terminal``; return that status."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _stack_status(cfn, stack_id)
        if status in terminal:
            return status
        time.sleep(3)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_id}: the run budget ended first; not graded")
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack whatever state it is in, and raise unless it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(ctx, cfn, stack_id, _DELETE_TERMINAL, 300.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}, not DELETE_COMPLETE")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ApiGatewayV2 SQS-SendMessage Integration reads back through
    GetIntegration with the exact ARN of the role the template created and the exact
    RequestParameters naming the template's queue, and the API is gone once the stack is deleted."""
    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    stack_name = ctx.unique_name("sim2real-cfn-integcreds-")
    api_name = ctx.unique_name("sim2real-cfn-integcreds-api-")
    role_name = ctx.unique_name("sim2real-cfn-integcreds-role-")
    queue_name = ctx.unique_name("sim2real-cfn-integcreds-q-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(api_name, role_name, queue_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))

    status = _wait_stack(ctx, cfn, stack_id, _CREATE_TERMINAL, 600.0)
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended {status!r}"
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    api_id = outputs["ApiId"]
    integration_id = outputs["IntegrationId"]
    partition = stack_id.split(":")[1]
    role_arn = f"arn:{partition}:iam::{ctx.account}:role/{role_name}"

    role = iam.get_role(RoleName=role_name)["Role"]
    assert (role["RoleName"], role["Arn"]) == (role_name, role_arn), (
        f"IAM GetRole reads {(role['RoleName'], role['Arn'])!r}, expected {(role_name, role_arn)!r}"
    )
    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]

    integration = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
    got = (
        integration.get("CredentialsArn"),
        integration.get("IntegrationSubtype"),
        integration.get("RequestParameters"),
    )
    want = (
        role_arn,
        "SQS-SendMessage",
        {"QueueUrl": queue_url, "MessageBody": "$request.body.msg"},
    )
    assert got == want, f"GetIntegration reads {got!r}, expected {want!r}"

    _delete_stack(ctx, cfn, stack_id)
    code, message = _error(lambda: agw.get_api(ApiId=api_id))
    assert (code, message) == (
        "NotFoundException",
        f"Invalid API identifier specified {ctx.account}:{api_id}",
    ), f"GetApi after delete returned {(code, message)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
