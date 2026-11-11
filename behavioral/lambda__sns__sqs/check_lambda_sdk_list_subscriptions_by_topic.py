"""lambda-sdk-list-subscriptions-by-topic."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-list-subscriptions-by-topic"
GROUP = "sdk-call"
SERVICES = ["lambda", "sns", "sqs"]

_TAG_KEY = "sim2real:managed"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role has sns:ListSubscriptionsByTopic lists a subscription created directly
    against SNS outside the function."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    topic_arn = _create_topic(ctx, sns)
    _queue_url, queue_arn = _create_queue(ctx, sqs)

    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    role_name, role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["lambda.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sns:ListSubscriptionsByTopic", "Resource": topic_arn}
            ],
        },
    )

    handler_body = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    sns = boto3.client('sns', region_name=event['region'])\n"
        "    resp = sns.list_subscriptions_by_topic(TopicArn=event['topic_arn'])\n"
        "    return {'arns': [s['SubscriptionArn'] for s in resp.get('Subscriptions', [])]}\n"
    )
    func_name = ctx.unique_name("sim2real-sdkcall-lst-")
    _create_function_with_retry(
        lam,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip_bytes(handler_body)},
        Timeout=30,
        Tags={_TAG_KEY: "true"},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_for_function_active(lam, func_name)

    payload = {"topic_arn": topic_arn, "region": ctx.region}
    result = _invoke_json_until(
        lam, func_name, payload, lambda r: sub_arn in r.get("arns", []), timeout_s=90
    )
    assert sub_arn in result["arns"], result


def _create_topic(ctx, sns):
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-sdkcall-topic-"),
        Tags=[{"Key": _TAG_KEY, "Value": "true"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue(ctx, sqs):
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sdkcall-q-"),
        tags={_TAG_KEY: "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_role(ctx, iam, trust_principals, managed_policy_arns=None, inline_policy=None):
    role_name = ctx.unique_name("sim2real-sdkcall-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": p}, "Action": "sts:AssumeRole"}
            for p in trust_principals
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": _TAG_KEY, "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    attached: list[str] = []
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        attached.append(policy_arn)
    inline_name = None
    if inline_policy:
        inline_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name, PolicyName=inline_name, PolicyDocument=json.dumps(inline_policy)
        )

    def _cleanup():
        if inline_name:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=inline_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for pa in attached:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pa)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_name, role_arn


def _lambda_zip_bytes(handler_body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_body)
    return buf.getvalue()


def _create_function_with_retry(lam, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                last_err = e
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "retry loop exited without capturing an error"
    raise last_err


def _wait_for_function_active(lam, func_name, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=func_name)["State"]
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active")


def _invoke_json_until(lam, func_name, payload, predicate, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=func_name, Payload=json.dumps(payload).encode())
        assert resp.get("FunctionError") is None, resp.get("FunctionError")
        last_result = json.loads(resp["Payload"].read())
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"predicate never satisfied, last result: {last_result}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
