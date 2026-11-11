"""iam-trust-sqs-wrong-principal-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-trust-sqs-wrong-principal-negative"
GROUP = "iam-trust"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction refuses a role trusting ec2.amazonaws.com (exact message), so no function
    exists and CreateEventSourceMapping fails with 'Function does not exist', while a role
    trusting lambda.amazonaws.com backs an SQS-triggered function that relays the message body."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    code = _lambda_zip_bytes(
        "import os, boto3\n"
        "_sqs = boto3.client('sqs')\n"
        "def handler(event, context):\n"
        "    dest = os.environ['DEST_QUEUE_URL']\n"
        "    n = 0\n"
        "    for record in event.get('Records', []):\n"
        "        _sqs.send_message(QueueUrl=dest, MessageBody=record['body'])\n"
        "        n += 1\n"
        "    return {'forwarded': n}\n"
    )

    # --- broken: wrong principal, no lambda.amazonaws.com / sqs.amazonaws.com trust ---
    _bad_role_name, bad_role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["ec2.amazonaws.com"],
        managed_policy_arns=["arn:aws:iam::aws:policy/AmazonSQSFullAccess"],
    )
    bad_func_name = ctx.unique_name("sim2real-iamtrust-sqsbad-")

    err_code, err_message = _client_error(lambda: lam.create_function(
        FunctionName=bad_func_name,
        Runtime="python3.12",
        Role=bad_role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        Timeout=15,
    ))
    assert err_code == "InvalidParameterValueException", err_code
    assert err_message == "The role defined for the function cannot be assumed by Lambda.", err_message

    not_found_code, not_found_message = _client_error(lambda: lam.get_function(FunctionName=bad_func_name))
    assert not_found_code == "ResourceNotFoundException", not_found_code
    expected = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_func_name}"
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # A function that was never created has no event source mapping to attach either --
    # the wrong-principal role forecloses the SQS-triggered execution context entirely,
    # not merely the CreateFunction call.
    bad_src_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-iamtrust-badsrc-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=bad_src_url))
    bad_src_arn = sqs.get_queue_attributes(QueueUrl=bad_src_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    esm_err_code, esm_err_message = _client_error(lambda: lam.create_event_source_mapping(
        EventSourceArn=bad_src_arn, FunctionName=bad_func_name, BatchSize=1, Enabled=True
    ))
    assert esm_err_code == "InvalidParameterValueException", esm_err_code
    assert esm_err_message == "Function does not exist", esm_err_message

    # --- positive control: role trusts lambda.amazonaws.com, backs a genuine
    # SQS-triggered execution context end to end ---
    _good_role_name, good_role_arn = _create_role(
        ctx,
        iam,
        trust_principals=["lambda.amazonaws.com"],
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        ],
    )
    good_func_name = ctx.unique_name("sim2real-iamtrust-sqsgood-")
    good_src_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-iamtrust-goodsrc-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=good_src_url))
    good_dst_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-iamtrust-gooddst-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=good_dst_url))
    good_src_arn = sqs.get_queue_attributes(QueueUrl=good_src_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    _create_function_with_retry(
        lam,
        FunctionName=good_func_name,
        Runtime="python3.12",
        Role=good_role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        Timeout=30,
        Environment={"Variables": {"DEST_QUEUE_URL": good_dst_url}},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_func_name))
    _wait_for_function_active(lam, good_func_name)

    mapping = lam.create_event_source_mapping(
        EventSourceArn=good_src_arn, FunctionName=good_func_name, BatchSize=1, Enabled=True
    )
    uuid = mapping["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _wait_for_mapping_enabled(lam, uuid)

    sqs.send_message(QueueUrl=good_src_url, MessageBody="iam-trust-sqs-relay-payload")
    body = _poll_for_message(sqs, good_dst_url, timeout_s=120.0)
    assert body == "iam-trust-sqs-relay-payload", body


def _create_role(ctx, iam, trust_principals, managed_policy_arns=None, inline_policy=None):
    role_name = ctx.unique_name("sim2real-iamtrust-role-")
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


def _lambda_zip_bytes(handler_body: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_body)
    return buf.getvalue()


def _client_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
    assert last_err is not None, "retry loop exited with no ClientError recorded"
    raise last_err


def _wait_for_function_active(lam, func_name, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=func_name)["State"]
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"function {func_name} never became Active")


def _wait_for_mapping_enabled(lam, uuid, timeout_s: float = 90.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_event_source_mapping(UUID=uuid)["State"]
        if state == "Enabled":
            return
        if state in ("Disabled", "Deleting"):
            raise AssertionError(f"event source mapping entered unexpected state {state!r}")
        time.sleep(interval_s)
    raise AssertionError(f"event source mapping {uuid} never became Enabled")


def _poll_for_message(sqs, queue_url, timeout_s: float = 90.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]["Body"]
        time.sleep(interval_s)
    raise AssertionError(f"no message arrived on {queue_url} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
