"""cfn-iam-role-trust-sqs-principal-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-trust-sqs-principal-positive"
GROUP = "iam-trust"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack-created role stores its sqs.amazonaws.com AssumeRole trust statement verbatim, and a
    caller assuming the role (it also trusts the account root) sends a message that a receive on
    the stack's queue returns unchanged."""
    role_name = _xname(ctx, "role")
    queue_name = _xname(ctx, "q")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    template = {
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
                                "Sid": "TrustSqsService",
                                "Effect": "Allow",
                                "Principal": {"Service": "sqs.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            },
                            {
                                "Sid": "TrustAccountRootForTest",
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                                "Action": "sts:AssumeRole",
                            },
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "send-to-queue",
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
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
        },
    }

    stack = _deploy_cfn(ctx, json.dumps(template))
    role_arn = stack["outputs"]["RoleArn"]
    queue_url = stack["outputs"]["QueueUrl"]

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    sqs_statement = next(
        (s for s in trust_doc["Statement"] if s.get("Principal", {}).get("Service") == "sqs.amazonaws.com"),
        None,
    )
    assert sqs_statement is not None, f"sqs.amazonaws.com trust statement was not persisted: {trust_doc}"
    assert sqs_statement["Effect"] == "Allow", sqs_statement
    assert sqs_statement["Action"] == "sts:AssumeRole", sqs_statement

    body = ctx.unique_name("delivered-via-assumed-role-")
    role_sqs = _assumed_role_client(ctx, role_arn, "sqs")
    _send_message_with_retry(role_sqs, queue_url, body, timeout_s=30.0)

    sqs = ctx.client("sqs")
    delivered = _wait_for_message(sqs, queue_url, timeout_s=30.0)
    assert delivered == body, f"expected message {body!r} at the queue, got {delivered!r}"


def _assumed_role_client(ctx: Any, role_arn: str, service: str) -> Any:
    """Assume role_arn (retrying past IAM's eventual-consistency propagation delay) and build a
    client for service using ONLY those temporary credentials — no fallback to ctx's own creds."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + 30.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-iam-trust-check")
            break
        except ClientError as err:
            last_err = err
            time.sleep(2.0)
    else:
        raise AssertionError(f"could not assume role {role_arn}: {last_err}")
    creds = resp["Credentials"]
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _send_message_with_retry(role_sqs, queue_url: str, body: str, *, timeout_s: float = 30.0) -> None:
    """Freshly-minted temporary credentials from a just-created role can take a few seconds to
    become valid everywhere (global STS/IAM propagation); retry on the transient
    InvalidClientTokenId/AccessDenied window instead of failing on the first attempt."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            role_sqs.send_message(QueueUrl=queue_url, MessageBody=body)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidClientTokenId", "AccessDenied"):
                raise
            last_exc = exc
            time.sleep(2.0)
    raise AssertionError(f"could not send message within {timeout_s}s: {last_exc}")


def _wait_for_message(sqs, queue_url: str, *, timeout_s: float = 30.0) -> str | None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            return m["Body"]
    return None


_XSVC_PREFIX = "sim2real-xsvc-"


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
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
