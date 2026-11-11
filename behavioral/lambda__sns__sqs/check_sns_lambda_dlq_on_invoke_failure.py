"""sns-lambda-dlq-on-invoke-failure."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-lambda-dlq-on-invoke-failure"
GROUP = "notification"
SERVICES = ["lambda", "sns", "sqs"]

_HANDLER_SRC = """
def handler(event, context):
    return {"ok": True}
"""

_SIGNAL_HANDLER_SRC_TMPL = """
import boto3
_sqs = boto3.client("sqs")
def handler(event, context):
    _sqs.send_message(QueueUrl="{queue_url}", MessageBody="invoked")
    return {{"ok": True}}
"""

_TAGS = {"sim2real:managed": "true"}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SNS->Lambda subscription without a lambda:InvokeFunction permission for SNS fails delivery
    and its RedrivePolicy DLQ receives the payload; a permitted twin on the same topic is invoked.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-dead-letter-queues.html"""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")

    dlq_url = ctx.unique_name("sim2real-xsvc-dlq-")
    dlq_url, dlq_arn = _create_queue(ctx, dlq_url)
    signal_url, signal_arn = _create_queue(ctx, ctx.unique_name("sim2real-xsvc-signal-"))

    role_arn = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_function(ctx, role_arn, _HANDLER_SRC)

    ok_role_arn = _create_lambda_role(
        ctx,
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": signal_arn}],
        },
    )
    ok_fn_name, ok_fn_arn = _create_function(
        ctx, ok_role_arn, _SIGNAL_HANDLER_SRC_TMPL.format(queue_url=signal_url)
    )

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-topic-"), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    # Grant SNS permission to deliver to the DLQ, referencing this topic as SourceArn.
    dlq_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "SQS:SendMessage",
            "Resource": dlq_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"Policy": json.dumps(dlq_policy)})

    # Positive control: the twin subscription DOES have lambda:InvokeFunction granted, on the
    # SAME topic, so the same publish() call below exercises both the working and the broken path
    # at once.
    lam.add_permission(
        FunctionName=ok_fn_name,
        StatementId="AllowSNSInvoke",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic_arn,
    )
    ok_sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=ok_fn_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=ok_sub_arn))

    # Deliberately DO NOT call lambda.add_permission() for sns.amazonaws.com on fn_arn: this is
    # exactly the client-side error condition ("owner changes the policy attached to the
    # subscribed endpoint") documented at
    # https://docs.aws.amazon.com/sns/latest/dg/sns-dead-letter-queues.html
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=fn_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))
    sns.set_subscription_attributes(
        SubscriptionArn=sub_arn,
        AttributeName="RedrivePolicy",
        AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
    )

    published_text = "undeliverable-because-no-invoke-permission"
    sns.publish(TopicArn=topic_arn, Message=published_text)

    # Positive control leg: the permitted twin is actually invoked by the SAME publish.
    signal_body = _poll_for_message(ctx, signal_url, timeout_s=60.0)
    assert signal_body == "invoked", f"positive-control function was never invoked: {signal_body!r}"

    body = _poll_for_message(ctx, dlq_url, timeout_s=60.0)
    envelope = json.loads(body)
    assert envelope.get("Message") == published_text, f"unexpected DLQ envelope: {envelope!r}"
    assert envelope.get("TopicArn") == topic_arn, f"expected TopicArn {topic_arn!r}, got {envelope.get('TopicArn')!r}"


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _TAGS.items()]


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=prefix, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_lambda_role(ctx, inline_policy: dict | None = None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv()
    )["Role"]["Arn"]
    # Register delete_role first: on_cleanup runs LIFO, so the inline-policy cleanup registered
    # below runs BEFORE this one, clearing the policy that would otherwise make delete_role fail
    # with DeleteConflict and leak the role.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_policy is not None:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    return role_arn


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_function(ctx, role_arn: str, handler_src: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    last_err: Exception | None = None
    resp = None
    for _ in range(10):
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _zip_bytes(handler_src)},
                Timeout=15,
                Tags=dict(_TAGS),
            )
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(2)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create function after retries: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name, resp["FunctionArn"]


def _poll_for_message(ctx, queue_url: str, timeout_s: float) -> str:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return msg["Body"]
    raise AssertionError(f"no message landed in the DLQ within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
