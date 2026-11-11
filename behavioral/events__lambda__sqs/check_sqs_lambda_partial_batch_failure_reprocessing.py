"""sqs-lambda-partial-batch-failure-reprocessing."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-lambda-partial-batch-failure-reprocessing"
GROUP = "state"
SERVICES = ["events", "lambda", "sqs"]


# timing:real-time — visibility: 8 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With ReportBatchItemFailures, a Lambda that fails one message of a batch makes only that message
    visible again in the source queue; the successful one is forwarded and deleted."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    # An SQS event source mapping requires the queue's VisibilityTimeout >= the function Timeout,
    # so both derive from one value.
    function_timeout_s = 5
    visibility_timeout_s = function_timeout_s + 3

    src_queue = _create_queue(ctx, extra_attrs={"VisibilityTimeout": str(visibility_timeout_s)})
    out_queue = _create_queue(ctx)

    role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "esm-perms": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                        "Resource": src_queue["arn"],
                    },
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": out_queue["arn"]},
                ],
            }
        },
    )
    assert function_timeout_s < visibility_timeout_s, "function timeout must fit inside the queue's visibility window"
    fn = _create_function(
        ctx,
        role_arn,
        code=(
            "import boto3, os\n"
            "def handler(event, context):\n"
            "    sqs = boto3.client('sqs')\n"
            "    failures = []\n"
            "    for record in event['Records']:\n"
            "        body = record['body']\n"
            "        if 'fail' in body:\n"
            "            failures.append({'itemIdentifier': record['messageId']})\n"
            "        else:\n"
            "            sqs.send_message(QueueUrl=os.environ['OUT_URL'], MessageBody=body)\n"
            "    return {'batchItemFailures': failures}\n"
        ),
        env={"OUT_URL": out_queue["url"]},
        timeout=function_timeout_s,
    )

    configured_timeout = lam.get_function_configuration(FunctionName=fn["name"])["Timeout"]
    configured_visibility = int(
        sqs.get_queue_attributes(QueueUrl=src_queue["url"], AttributeNames=["VisibilityTimeout"])[
            "Attributes"
        ]["VisibilityTimeout"]
    )
    assert configured_timeout == function_timeout_s, (
        f"expected function Timeout {function_timeout_s}, got {configured_timeout}"
    )
    assert configured_visibility == visibility_timeout_s, (
        f"expected queue VisibilityTimeout {visibility_timeout_s}, got {configured_visibility}"
    )
    assert configured_timeout < configured_visibility, (
        f"function timeout {configured_timeout} must be strictly inside the queue's "
        f"visibility window {configured_visibility}"
    )

    mapping = lam.create_event_source_mapping(
        EventSourceArn=src_queue["arn"],
        FunctionName=fn["name"],
        BatchSize=10,
        FunctionResponseTypes=["ReportBatchItemFailures"],
    )
    uuid = mapping["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid)["State"],
        lambda s: s == "Enabled",
        timeout_s=60.0,
        interval_s=2.0,
    )

    sqs.send_message(QueueUrl=src_queue["url"], MessageBody="keep-this-one")
    sqs.send_message(QueueUrl=src_queue["url"], MessageBody="fail-this-one")

    delivered = _poll_until(
        lambda: _drain(sqs, out_queue["url"]),
        lambda msgs: len(msgs) >= 1,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert delivered[0]["Body"] == "keep-this-one", (
        f"expected the successfully processed message forwarded to the output queue, got {delivered!r}"
    )

    # Disable the mapping so the receive below does not race it for the redelivered message.
    lam.update_event_source_mapping(UUID=uuid, Enabled=False)
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid)["State"],
        lambda s: s == "Disabled",
        timeout_s=60.0,
        interval_s=2.0,
    )

    # Accumulate across the window: an undeleted successful message could reappear in a later
    # receive than the failed one.
    seen_src_bodies: set[str] = set()
    src_deadline = time.monotonic() + 30.0
    while time.monotonic() < src_deadline and "fail-this-one" not in seen_src_bodies:
        for msg in _drain(sqs, src_queue["url"], wait=5):
            seen_src_bodies.add(msg["Body"])
    assert "fail-this-one" in seen_src_bodies, (
        f"failed message was never redelivered to the source queue; saw {sorted(seen_src_bodies)}"
    )
    assert "keep-this-one" not in seen_src_bodies, (
        "successfully processed message reappeared in the source queue -- the target failed to "
        f"delete it after successful processing; saw {sorted(seen_src_bodies)}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _drain(sqs, url, max_msgs=10, wait=2):
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_msgs, WaitTimeSeconds=wait)
    return resp.get("Messages", [])


def _create_role(ctx, trust_service, inline_policies=None, managed_arns=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        for pname in list((inline_policies or {}).keys()):
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for marn in (managed_arns or []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=marn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for marn in (managed_arns or []):
        iam.attach_role_policy(RoleName=name, PolicyArn=marn)
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _create_function(ctx, role_arn, code, handler="handler.handler", env=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", code)
    zip_bytes = buf.getvalue()
    deadline = time.monotonic() + 40.0
    resp = None
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2,
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue(ctx, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    suffix = ".fifo" if fifo else ""
    name = ctx.unique_name("sim2real-q-") + suffix
    attrs = dict(extra_attrs or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
