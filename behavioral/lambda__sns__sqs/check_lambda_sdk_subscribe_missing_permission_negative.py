"""lambda-sdk-subscribe-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-subscribe-missing-permission-negative"
GROUP = "sdk-call"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without sns:Subscribe gets AuthorizationError and the topic has no
    subscription, while an otherwise identical function whose role has sns:Subscribe creates one."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    topic_arn = _create_topic(ctx, sns)
    _queue_url, queue_arn = _create_queue(ctx, sqs)

    handler_body = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    sns = boto3.client('sns', region_name=event['region'])\n"
        "    try:\n"
        "        resp = sns.subscribe(TopicArn=event['topic_arn'], Protocol='sqs', "
        "Endpoint=event['queue_arn'], ReturnSubscriptionArn=True)\n"
        "        return {'ok': True, 'subscription_arn': resp['SubscriptionArn']}\n"
        "    except Exception as e:\n"
        "        code = getattr(e, 'response', {}).get('Error', {}).get('Code')\n"
        "        return {'ok': False, 'error_code': code}\n"
    )
    payload = {"topic_arn": topic_arn, "queue_arn": queue_arn, "region": ctx.region}

    # --- broken: role has only basic execution (logs), no sns permissions ---
    _bad_role_name, bad_role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["lambda.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    bad_func_name = ctx.unique_name("sim2real-sdkcall-subneg-bad-")
    _create_function_with_retry(
        lam,
        FunctionName=bad_func_name,
        Runtime="python3.12",
        Role=bad_role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip_bytes(handler_body)},
        Timeout=30,
        Tags={"simparity-check": CHECK},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=bad_func_name))
    _wait_for_function_active(lam, bad_func_name)

    bad_result = _invoke_json_until(
        lam, bad_func_name, payload, lambda r: r.get("ok") is False, timeout_s=60
    )
    assert bad_result["error_code"] == "AuthorizationError", bad_result

    # effect absent: the topic still has no subscriptions at all
    subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert subs == [], subs

    # --- positive control: role does have sns:Subscribe on this topic ---
    _good_role_name, good_role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["lambda.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sns:Subscribe", "Resource": topic_arn}],
        },
    )
    good_func_name = ctx.unique_name("sim2real-sdkcall-subneg-good-")
    _create_function_with_retry(
        lam,
        FunctionName=good_func_name,
        Runtime="python3.12",
        Role=good_role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip_bytes(handler_body)},
        Timeout=30,
        Tags={"simparity-check": CHECK},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_func_name))
    _wait_for_function_active(lam, good_func_name)

    good_result = _invoke_json_until(
        lam, good_func_name, payload, lambda r: r.get("ok") is True, timeout_s=90
    )
    assert good_result["ok"] is True, good_result
    sub_arn = good_result["subscription_arn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    subs_after = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert any(s["SubscriptionArn"] == sub_arn for s in subs_after), subs_after


def _create_topic(ctx, sns):
    arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-sdkcall-topic-"),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


def _create_queue(ctx, sqs):
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sdkcall-q-"),
        tags={"simparity-check": CHECK},
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
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
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
    assert last_err is not None
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
