"""sns-lambda-destination-onfailure-to-sqs."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-lambda-destination-onfailure-to-sqs"
GROUP = "notification"
SERVICES = ["lambda", "sns", "sqs"]

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

_HANDLER_SRC = """
def handler(event, context):
    raise RuntimeError("intentional-failure-for-destination-test")
"""


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda async invocation OnFailure destination pointed at an SNS topic fans the failure
    event out to a subscribed SQS queue, carrying the original request payload and error info."""
    sns = ctx.client("sns")
    lam = ctx.client("lambda")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-topic-"), Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url, queue_arn = _create_queue(ctx)
    _allow_sns_to_send_to_queue(ctx, queue_url, queue_arn, topic_arn)
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    role_arn = _create_lambda_role(ctx, topic_arn)
    fn_name, _fn_arn = _create_function(ctx, role_arn)

    # No retries so the OnFailure destination fires after exactly one failed attempt.
    lam.put_function_event_invoke_config(
        FunctionName=fn_name,
        MaximumRetryAttempts=0,
        DestinationConfig={"OnFailure": {"Destination": topic_arn}},
    )

    marker = ctx.unique_name("payload-marker-")
    lam.invoke(FunctionName=fn_name, InvocationType="Event", Payload=json.dumps({"marker": marker}).encode())

    body = _poll_for_message(ctx, queue_url, timeout_s=90.0)
    envelope = json.loads(body)
    failure_event = json.loads(envelope["Message"])
    actual_fn_arn = failure_event["requestContext"]["functionArn"]
    assert fn_name in actual_fn_arn, f"expected functionArn to contain {fn_name!r}, got {actual_fn_arn!r}"
    actual_marker = failure_event["requestPayload"]["marker"]
    assert actual_marker == marker, f"expected requestPayload.marker {marker!r}, got {actual_marker!r}"
    actual_error_type = failure_event["responsePayload"]["errorType"]
    assert actual_error_type == "RuntimeError", f"expected errorType 'RuntimeError', got {actual_error_type!r}"
    actual_error_message = failure_event["responsePayload"]["errorMessage"]
    assert "intentional-failure-for-destination-test" in actual_error_message, (
        f"expected errorMessage to contain 'intentional-failure-for-destination-test', got {actual_error_message!r}"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-q-"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _allow_sns_to_send_to_queue(ctx, queue_url: str, queue_arn: str, topic_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "SQS:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


def _create_lambda_role(ctx, publish_topic_arn: str) -> str:
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
    # The execution role -- not a service-linked role -- is what Lambda uses to publish the
    # failure-destination event, so it must be allowed sns:Publish on the destination topic.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="publish-destination",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": publish_topic_arn}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="publish-destination"))
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
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    # The function auto-creates /aws/lambda/<name> on first invoke; that log group survives
    # function deletion, so delete it.
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    )
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
    raise AssertionError(f"no failure-destination event delivered within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
