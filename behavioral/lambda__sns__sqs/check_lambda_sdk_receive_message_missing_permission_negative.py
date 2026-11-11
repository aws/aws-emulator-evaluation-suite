"""lambda-sdk-receive-message-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-receive-message-missing-permission-negative"
GROUP = "sdk-call"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role without sqs:ReceiveMessage gets AccessDenied and the queue polls to one visible
    message; a role with it receives the message, which a fresh long-poll receive then cannot see
    while it is in flight."""
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    queue_url, queue_arn = _create_queue(ctx, sqs)
    body_text = ctx.unique_name("payload-")
    sqs.send_message(QueueUrl=queue_url, MessageBody=body_text)

    handler_body = (
        "import boto3\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs', region_name=event['region'])\n"
        "    try:\n"
        "        resp = sqs.receive_message(QueueUrl=event['queue_url'], MaxNumberOfMessages=10, WaitTimeSeconds=5)\n"
        "        msgs = resp.get('Messages', [])\n"
        "        return {'ok': True, 'count': len(msgs), 'bodies': [m['Body'] for m in msgs]}\n"
        "    except Exception as e:\n"
        "        code = getattr(e, 'response', {}).get('Error', {}).get('Code')\n"
        "        return {'ok': False, 'error_code': code}\n"
    )
    payload = {"queue_url": queue_url, "region": ctx.region}

    # --- broken: role has only basic execution (logs), no sqs permissions ---
    _bad_role_name, bad_role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["lambda.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
    )
    bad_func_name = ctx.unique_name("sim2real-sdkcall-recvneg-bad-")
    _create_function_with_retry(
        lam,
        FunctionName=bad_func_name,
        Runtime="python3.12",
        Role=bad_role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip_bytes(handler_body)},
        Timeout=30,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=bad_func_name))
    _wait_for_function_active(lam, bad_func_name)

    bad_result = _invoke_json_until(
        lam, bad_func_name, payload, lambda r: r.get("ok") is False, timeout_s=60
    )
    assert bad_result["error_code"] == "AccessDenied", bad_result

    # effect absent: the message is still sitting on the queue, untouched
    _poll_queue_counters(ctx, sqs, queue_url, {"ApproximateNumberOfMessages": "1"})

    # --- positive control: role does have sqs:ReceiveMessage on this queue ---
    _good_role_name, good_role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["lambda.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": queue_arn}],
        },
    )
    good_func_name = ctx.unique_name("sim2real-sdkcall-recvneg-good-")
    _create_function_with_retry(
        lam,
        FunctionName=good_func_name,
        Runtime="python3.12",
        Role=good_role_arn,
        Handler="index.handler",
        Code={"ZipFile": _lambda_zip_bytes(handler_body)},
        Timeout=30,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_func_name))
    _wait_for_function_active(lam, good_func_name)

    good_result = _invoke_json_until(
        lam, good_func_name, payload, lambda r: r.get("ok") is True and r.get("count", 0) >= 1, timeout_s=90
    )
    assert good_result["ok"] is True, good_result
    assert body_text in good_result["bodies"], good_result

    # independent read at the destination: the permitted receive really reached SQS (not just
    # a Lambda-reported success) — the message is now in flight, invisible to a fresh receive
    # for the queue's default 30 s VisibilityTimeout; a long poll consults every SQS server,
    # unlike the approximate in-flight counter, which may lag up to a minute
    recheck = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    assert body_text not in [m["Body"] for m in recheck.get("Messages", [])], recheck


def _create_queue(ctx, sqs):
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-sdkcall-q-"))["QueueUrl"]
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc))
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_queue_counters(ctx, sqs, queue_url, expected, cap_s=90.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value.

    The ApproximateNumberOf* counters may lag up to a minute after producers stop
    (SQS GetQueueAttributes docs), so a single read is not a verdict."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s counter wait ended (last observed {observed}); not graded"
                )
            raise AssertionError(f"queue counters never reached {expected} within {cap_s}s; last observed {observed}")
        time.sleep(3)


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
