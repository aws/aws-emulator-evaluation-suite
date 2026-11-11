"""cfn-iam-role-trusts-sqs-service-principal."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-trusts-sqs-service-principal"
GROUP = "iam-trust"
SERVICES = ["events", "lambda", "sqs"]

_ROLE_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"RoleNameParam": {"Type": "String"}},
    "Resources": {
        "SqsManagedRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {"Ref": "RoleNameParam"},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "sqs.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
            },
        },
    },
    "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["SqsManagedRole", "Arn"]}}},
})


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """IAM stores a CloudFormation role's trust policy allowing sqs.amazonaws.com as written, and a
    queue encrypted with a customer managed key whose policy names sqs.amazonaws.com sends and
    receives the exact body."""
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = _xname(ctx, "sqs-trust-role")
    result = _deploy_cfn(ctx, _ROLE_TEMPLATE, parameters={"RoleNameParam": role_name})
    role_arn = result["outputs"]["RoleArn"]
    assert role_arn.endswith(f":role/{role_name}"), (
        f"CFN output RoleArn does not name the role this check created: {role_arn!r}, "
        f"expected it to end with ':role/{role_name}'"
    )

    role_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    statement = role_doc["Statement"][0]
    assert statement["Effect"] == "Allow", (
        f"the CFN-deployed role's trust statement Effect is not Allow: {statement!r}"
    )
    assert statement["Principal"]["Service"] == "sqs.amazonaws.com", (
        f"IAM did not persist the sqs.amazonaws.com trust principal: got "
        f"{statement['Principal']!r}"
    )

    admin_statement = {
        "Sid": "AllowRootAdmin",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }
    trust_statement = {
        "Sid": "AllowSqsServicePrincipalForQueueOps",
        "Effect": "Allow",
        "Principal": {"Service": "sqs.amazonaws.com"},
        "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
        "Resource": "*",
        "Condition": {"StringEquals": {"kms:CallerAccount": account_id}},
    }

    key = kms.create_key(
        Description="sim2real sqs-trust CMK",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": [admin_statement, trust_statement]}),
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _xsvc_resource_tags().items()],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    queue_name = _xname(ctx, "sse-queue")
    queue_url = sqs.create_queue(
        QueueName=queue_name,
        Attributes={"KmsMasterKeyId": key_id},
        tags=_xsvc_resource_tags(),
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    body = f"sqs-trust-payload-{queue_name}"

    def _round_trip():
        sqs.send_message(QueueUrl=queue_url, MessageBody=body)
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        return resp.get("Messages", [])

    # KMS key policy propagation can lag briefly; retry the whole send/receive round trip.
    messages = _poll_until(
        _round_trip, lambda m: len(m) == 1, timeout_s=45, interval_s=3.0,
        description="SSE-KMS queue round trip against the CMK",
    )
    assert messages[0]["Body"] == body, (
        f"the SSE-KMS round trip did not return the sent body byte-exact: got "
        f"{messages[0]['Body']!r}, sent {body!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])


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
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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
    template_body = template.read_text() if hasattr(template, "read_text") else template
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
