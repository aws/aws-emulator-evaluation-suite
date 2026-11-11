"""lambda-sdk-subscribe-missing-permission-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-sdk-subscribe-missing-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["lambda", "sns", "sqs"]

_CODE_SUBSCRIBE = """
import boto3

def handler(event, context):
    sns = boto3.client("sns")
    try:
        resp = sns.subscribe(
            TopicArn=event["topic_arn"],
            Protocol="sqs",
            Endpoint=event["queue_arn"],
            ReturnSubscriptionArn=True,
        )
        return {"ok": True, "subscription_arn": resp["SubscriptionArn"]}
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        message = getattr(exc, "response", {}).get("Error", {}).get("Message")
        return {"ok": False, "error_code": code, "message": message}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking sns:Subscribe gets AuthorizationError and creates no subscription;
    a role with the permission (positive control) then subscribes successfully."""
    topic = _create_topic(ctx)
    queue = _create_queue(ctx)
    sns = ctx.client("sns")

    deny_role = _create_role(ctx, None)
    deny_fn = _create_function(ctx, deny_role, _CODE_SUBSCRIBE)
    denied = _invoke(ctx, deny_fn, {"topic_arn": topic["arn"], "queue_arn": queue["arn"]})
    assert denied["ok"] is False, denied
    assert denied["error_code"] == "AuthorizationError", denied
    principal = f"arn:aws:sts::{topic['arn'].split(':')[4]}:assumed-role/{deny_role.rsplit('/', 1)[1]}/{deny_fn}"
    expected_message = (
        f"User: {principal} is not authorized to perform: SNS:Subscribe on resource: {topic['arn']} "
        "because no identity-based policy allows the SNS:Subscribe action"
    )
    assert denied["message"] == expected_message, f"{denied!r} != {expected_message!r}"

    # effect absent: no subscription was created on the topic
    subs = sns.list_subscriptions_by_topic(TopicArn=topic["arn"])["Subscriptions"]
    assert subs == [], subs

    # positive control: the same call succeeds once sns:Subscribe is granted
    allow_role = _create_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sns:Subscribe", "Resource": topic["arn"]}],
        },
    )
    allow_fn = _create_function(ctx, allow_role, _CODE_SUBSCRIBE)
    allowed = _invoke(ctx, allow_fn, {"topic_arn": topic["arn"], "queue_arn": queue["arn"]})
    assert allowed["ok"] is True, allowed
    sub_arn = allowed["subscription_arn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    subs_after = sns.list_subscriptions_by_topic(TopicArn=topic["arn"])["Subscriptions"]
    assert any(s["SubscriptionArn"] == sub_arn for s in subs_after), subs_after


_PREFIX = "sim2real-snssqslambda-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _lambda_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx: Any, inline_policy: dict | None) -> str:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv())
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_policy is not None:
        iam.put_role_policy(RoleName=role_name, PolicyName="perm", PolicyDocument=json.dumps(inline_policy))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="perm"))
    return role_arn


def _wait_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _create_function(ctx: Any, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    zip_bytes = _lambda_zip(code)
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags=_resource_tags(),
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    else:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return name


def _invoke(ctx: Any, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    body = json.loads(resp["Payload"].read())
    assert "FunctionError" not in resp, f"unexpected FunctionError: {resp.get('FunctionError')}, body={body}"
    return body


def _create_queue(ctx: Any, attrs: dict | None = None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), Attributes=attrs or {}, tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_topic(ctx: Any) -> dict[str, str]:
    sns = ctx.client("sns")
    arn = sns.create_topic(Name=_xname(ctx, "topic"), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return {"arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
