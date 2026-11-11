"""iam-role-trust-sqs-principal."""
from __future__ import annotations

import io
import json
import time
import zipfile
from urllib.parse import unquote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-trust-sqs-principal"
GROUP = "iam-trust"
SERVICES = ["lambda", "sns", "sqs"]

_MANAGED_TAG_KEY = "sim2real:managed"


def _tag_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


def _tag_dict() -> dict[str, str]:
    return {kv["Key"]: kv["Value"] for kv in _tag_kv()}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting lambda.amazonaws.com and sqs.amazonaws.com keeps both principals and backs an
    SQS-triggered function that relays the message body to a second queue."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    role_name, role_arn = _create_role(
        ctx,
        iam,
        # lambda.amazonaws.com is the statement Lambda actually needs to assume the
        # role; sqs.amazonaws.com is included because this role exists specifically
        # to serve an SQS-triggered execution context.
        trust_principals=["lambda.amazonaws.com", "sqs.amazonaws.com"],
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
        ],
    )

    # Independent read: the role's stored trust document must actually carry both
    # statements. Without this, a target that silently drops or merges the second
    # trust statement would pass this check identically -- only lambda.amazonaws.com
    # is exercised by the relay below, since Lambda (not SQS) is what assumes the role.
    stored_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    if isinstance(stored_doc, str):
        stored_doc = json.loads(unquote(stored_doc))
    stored_principals = {
        stmt["Principal"]["Service"] for stmt in stored_doc["Statement"] if stmt["Effect"] == "Allow"
    }
    assert stored_principals == {"lambda.amazonaws.com", "sqs.amazonaws.com"}, stored_principals

    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iamtrust-src-"), tags=_tag_dict()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    dst_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iamtrust-dst-"), tags=_tag_dict()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dst_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    func_name = ctx.unique_name("sim2real-iamtrust-relay-")
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
    _create_function_with_retry(
        lam,
        FunctionName=func_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": code},
        Timeout=30,
        Environment={"Variables": {"DEST_QUEUE_URL": dst_url}},
        Tags=_tag_dict(),
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_for_function_active(lam, func_name)

    mapping = lam.create_event_source_mapping(
        EventSourceArn=src_arn, FunctionName=func_name, BatchSize=1, Enabled=True
    )
    uuid = mapping["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _wait_for_mapping_enabled(lam, uuid)

    sqs.send_message(QueueUrl=src_url, MessageBody="iam-trust-relay-payload")

    body = _poll_for_message(sqs, dst_url, timeout_s=120.0)
    assert body == "iam-trust-relay-payload", body


def _create_role(ctx, iam, trust_principals, managed_policy_arns=None, inline_policy=None):
    role_name = ctx.unique_name("sim2real-iamtrust-role-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": p}, "Action": "sts:AssumeRole"}
            for p in trust_principals
        ],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_doc), Tags=_tag_kv()
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
