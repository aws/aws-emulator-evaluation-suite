"""snstrig-lambda-async-retry-exhausted-onfailure-to-sqs."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snstrig-lambda-async-retry-exhausted-onfailure-to-sqs"
GROUP = "async-destinations"
SERVICES = ["lambda", "sns", "sqs"]

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

_HANDLER_SRC = """
def handler(event, context):
    raise RuntimeError("intentional-failure-for-snstrig-destination-test")
"""

#: SNS invokes the subscribed function asynchronously, through the SAME async-invoke machinery
#: a direct Event invoke uses: MaximumRetryAttempts=1 means 1 initial attempt plus 1 retry (an
#: exponential backoff of roughly a minute between them) before the OnFailure destination fires.
_DELIVERY_DEADLINE_S = 420.0
#: Spacing between fresh probes while delivery has not yet landed -- guards against the one
#: propagation race that can lose a single publish: the add_permission grant not yet being
#: honoured by SNS's first invoke attempt.
_PROBE_INTERVAL_S = 30.0


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An always-failing SNS-triggered function with MaximumRetryAttempts=1 sends OnFailure to SQS.
    The record is RetriesExhausted after 2 invokes, its requestPayload is the exact SNS envelope
    that was published, and its responsePayload carries the handler's RuntimeError."""
    sns = ctx.client("sns")
    lam = ctx.client("lambda")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx, queue_arn)
    fn_name, fn_arn = _create_function(ctx, role_arn)

    lam.put_function_event_invoke_config(
        FunctionName=fn_name,
        MaximumRetryAttempts=1,
        DestinationConfig={"OnFailure": {"Destination": queue_arn}},
    )
    cfg = lam.get_function_event_invoke_config(FunctionName=fn_name)
    assert cfg["MaximumRetryAttempts"] == 1, f"retry config not stored: {cfg.get('MaximumRetryAttempts')!r}"

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-topic-"), Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    lam.add_permission(
        FunctionName=fn_name, StatementId="sns-invoke", Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com", SourceArn=topic_arn,
    )
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="lambda", Endpoint=fn_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    record, sent_message, sent_message_id = _publish_until_delivered(ctx, sns, topic_arn, queue_url)

    rc = record.get("requestContext", {})
    assert rc.get("condition") == "RetriesExhausted", (
        f"expected requestContext.condition 'RetriesExhausted' after MaximumRetryAttempts=1 "
        f"exhausted both attempts, got {rc.get('condition')!r}: {record!r}"
    )
    assert rc.get("approximateInvokeCount") == 2, (
        f"MaximumRetryAttempts=1 must yield exactly 1 initial attempt + 1 retry = "
        f"approximateInvokeCount 2, got {rc.get('approximateInvokeCount')!r}"
    )
    assert fn_name in rc.get("functionArn", ""), f"expected functionArn to contain {fn_name!r}, got {rc.get('functionArn')!r}"

    payload = record.get("requestPayload", {})
    records = payload.get("Records", [])
    assert len(records) == 1, f"the SNS envelope must carry exactly one record, got {records!r}"
    envelope = records[0]
    head = {k: envelope.get(k) for k in ("EventSource", "EventVersion", "EventSubscriptionArn")}
    assert head == {"EventSource": "aws:sns", "EventVersion": "1.0", "EventSubscriptionArn": sub_arn}, (
        f"requestPayload record header is {head!r}; the destination must carry the SNS trigger's "
        f"own envelope, not a synthesised direct-invoke payload"
    )
    sns_block = envelope.get("Sns", {})
    assert sns_block.get("TopicArn") == topic_arn, f"Sns.TopicArn is {sns_block.get('TopicArn')!r}, expected {topic_arn!r}"
    assert sns_block.get("MessageId") == sent_message_id, (
        f"Sns.MessageId is {sns_block.get('MessageId')!r}, expected the publish's own {sent_message_id!r}"
    )
    assert sns_block.get("Message") == sent_message, (
        f"Sns.Message is {sns_block.get('Message')!r}, expected the published body {sent_message!r}"
    )

    response_payload = record.get("responsePayload", {})
    assert response_payload.get("errorType") == "RuntimeError", (
        f"expected responsePayload.errorType 'RuntimeError', got {response_payload.get('errorType')!r}"
    )
    assert response_payload.get("errorMessage") == "intentional-failure-for-snstrig-destination-test", (
        f"expected responsePayload.errorMessage to be the handler's error text, got "
        f"{response_payload.get('errorMessage')!r}"
    )



def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-q-"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_lambda_role(ctx, destination_queue_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # The execution role -- not a service-linked role -- is what Lambda uses to write the
    # async-invoke failure record, so it must be allowed sqs:SendMessage on the destination queue.
    # Basic log permissions are included so a real failure in the handler is diagnosable from
    # CloudWatch Logs rather than from a silently-empty destination.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="onfailure-destination",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": destination_queue_arn},
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:aws:logs:*:*:*",
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="onfailure-destination"))
    return role_arn


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_function(ctx, role_arn: str) -> tuple[str, str]:
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
                Code={"ZipFile": _zip_bytes(_HANDLER_SRC)},
                Timeout=15,
                Tags=dict(_xsvc_resource_tags()),
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
    # The function auto-creates /aws/lambda/<name> on first invoke and that group survives the
    # function; registered first so LIFO reaps it after delete_function stops new invocations.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name, resp["FunctionArn"]


def _reap_log_group(ctx, function_name: str, *, quiet_reads: int = 3, max_rounds: int = 12,
                    interval_s: float = 5.0) -> None:
    """delete_function never removes /aws/lambda/<fn>, and a late log flush can recreate it after
    a delete, so delete until the group has read absent several times running; raise if it keeps
    reappearing."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    quiet = 0
    for _ in range(max_rounds):
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if any(g["logGroupName"] == group for g in found):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= quiet_reads:
                return
        time.sleep(interval_s)
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _publish_until_delivered(ctx, sns, topic_arn: str, queue_url: str) -> tuple[dict, str, str]:
    """Publish fresh probes on an interval, polling for ANY of their destination records.

    A single publish can race SNS's own first invoke attempt against the add_permission grant
    not yet being honoured -- unlike a direct Event invoke, this is the one hop a push trigger
    adds. Each probe's own retry-exhaustion round trip can take well over the probe interval, so
    every marker ever sent stays eligible for a match for the life of the poll -- an in-flight
    probe's record is never discarded just because a newer probe has since gone out.
    """
    sqs = ctx.client("sqs")
    sent: dict[str, str] = {}
    deadline = time.monotonic() + _DELIVERY_DEADLINE_S
    next_probe_at = time.monotonic()
    while time.monotonic() < deadline:
        if time.monotonic() >= next_probe_at:
            marker = ctx.unique_name("sim2real-xsvc-probe-")
            sent[marker] = sns.publish(TopicArn=topic_arn, Message=marker)["MessageId"]
            next_probe_at = time.monotonic() + _PROBE_INTERVAL_S
        remaining = max(1, int(min(deadline, next_probe_at) - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=min(10, remaining)
        )
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            record = json.loads(msg["Body"])
            records = (record.get("requestPayload") or {}).get("Records") or []
            marker = records[0].get("Sns", {}).get("Message") if records else None
            if marker in sent:
                return record, marker, sent[marker]
    raise AssertionError(
        f"no OnFailure destination record delivered within {_DELIVERY_DEADLINE_S}s of "
        f"publishing {len(sent)} probe(s)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
