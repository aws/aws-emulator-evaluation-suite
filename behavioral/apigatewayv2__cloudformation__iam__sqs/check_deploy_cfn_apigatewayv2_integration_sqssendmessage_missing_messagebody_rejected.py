"""deploy-cfn-apigatewayv2-integration-sqssendmessage-missing-messagebody-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-apigatewayv2-integration-sqssendmessage-missing-messagebody-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_MISSING_MESSAGE_BODY = (
    "Operation: SQS-SendMessage requires enabling passthrough, or defining all of the following "
    "parameters in the parameter mapping: [QueueUrl, MessageBody] "
    "(Service: ApiGatewayV2, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(api_name: str, role_name: str, queue_name: str, with_message_body: bool) -> str:
    request_parameters = {"QueueUrl": {"Ref": "Queue"}}
    if with_message_body:
        request_parameters["MessageBody"] = "$request.body.msg"
    body = {
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
                    "RequestParameters": request_parameters,
                },
            },
        },
        "Outputs": {
            "ApiId": {"Value": {"Ref": "Api"}},
            "IntegrationId": {"Value": {"Ref": "Integration"}},
        },
    }
    return json.dumps(body)


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


def _create(ctx, cfn, stack_name: str, template: str) -> tuple[str, str]:
    """CreateStack, its teardown registered at once; the stack's terminal create status."""
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack_id))
    return stack_id, _wait_stack(ctx, cfn, stack_id, _CREATE_TERMINAL, 600.0)


def _handler_reason(reason: str) -> tuple[str, str]:
    """``(message, HandlerErrorCode)`` of a resource-handler reason, masking only the Request ID,
    RequestToken and SDK attempt count; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    message = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", m["message"])
    message = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)
    return message, m["code"]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ApiGatewayV2 SQS-SendMessage Integration without a MessageBody
    RequestParameter fails with API Gateway's exact refusal and leaves no Api; the same template
    with MessageBody set deploys, reading back the template's queue URL and role ARN."""
    cfn = ctx.client("cloudformation")
    agw = ctx.client("apigatewayv2")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    bad_stack_name = ctx.unique_name("sim2real-cfn-sqssubtype-bad-")
    bad_api_name = ctx.unique_name("sim2real-cfn-sqssubtype-bad-api-")
    bad_role_name = ctx.unique_name("sim2real-cfn-sqssubtype-bad-role-")
    bad_queue_name = ctx.unique_name("sim2real-cfn-sqssubtype-bad-q-")
    bad_id, status = _create(
        ctx,
        cfn,
        bad_stack_name,
        _template(bad_api_name, bad_role_name, bad_queue_name, with_message_body=False),
    )
    assert status == "ROLLBACK_COMPLETE", f"integration missing MessageBody settled at {status!r}"

    events = [
        e
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=bad_id)
        for e in page["StackEvents"]
    ]
    failed = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == "Integration" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(failed) == 1, f"expected exactly one Integration CREATE_FAILED row, got {failed!r}"
    got = _handler_reason(failed[0])
    assert got == _MISSING_MESSAGE_BODY, (
        f"Integration CREATE_FAILED reason masks to {got!r}, expected {_MISSING_MESSAGE_BODY!r}; "
        f"raw {failed[0]!r}"
    )

    apis = [a for page in agw.get_paginator("get_apis").paginate() for a in page["Items"]]
    left = [a["ApiId"] for a in apis if a["Name"] == bad_api_name]
    assert left == [], f"an Api named {bad_api_name!r} exists after the rollback: {left!r}"

    # Positive control: the identical template with MessageBody present reaches CREATE_COMPLETE.
    good_stack_name = ctx.unique_name("sim2real-cfn-sqssubtype-good-")
    good_api_name = ctx.unique_name("sim2real-cfn-sqssubtype-good-api-")
    good_role_name = ctx.unique_name("sim2real-cfn-sqssubtype-good-role-")
    good_queue_name = ctx.unique_name("sim2real-cfn-sqssubtype-good-q-")
    good_id, status = _create(
        ctx,
        cfn,
        good_stack_name,
        _template(good_api_name, good_role_name, good_queue_name, with_message_body=True),
    )
    assert status == "CREATE_COMPLETE", f"the valid template settled at {status!r}"
    good_outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=good_id)["Stacks"][0].get("Outputs", [])
    }
    queue_url = sqs.get_queue_url(QueueName=good_queue_name)["QueueUrl"]
    role_arn = iam.get_role(RoleName=good_role_name)["Role"]["Arn"]
    good_integration = agw.get_integration(
        ApiId=good_outputs["ApiId"], IntegrationId=good_outputs["IntegrationId"]
    )
    got = (good_integration.get("CredentialsArn"), good_integration.get("RequestParameters"))
    want = (role_arn, {"QueueUrl": queue_url, "MessageBody": "$request.body.msg"})
    assert got == want, f"control GetIntegration reads {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
