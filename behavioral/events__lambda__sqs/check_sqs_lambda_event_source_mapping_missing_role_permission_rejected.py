"""sqs-lambda-event-source-mapping-missing-role-permission-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-lambda-event-source-mapping-missing-role-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["events", "lambda", "sqs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventSourceMapping rejects a role lacking sqs:ReceiveMessage with
    InvalidParameterValueException and its exact message and creates no mapping; a permitted
    role's mapping reaches Enabled."""
    lam = ctx.client("lambda")

    queue = _create_queue(ctx)

    bare_role_arn = _create_role(ctx, "lambda.amazonaws.com")
    bare_fn = _create_function(
        ctx,
        bare_role_arn,
        code="def handler(event, context):\n    return {'ok': True}\n",
    )

    code, message = _error(
        ctx,
        lambda: lam.create_event_source_mapping(
            EventSourceArn=queue["arn"], FunctionName=bare_fn["name"], BatchSize=10
        ),
    )
    assert code == "InvalidParameterValueException", (
        f"expected CreateEventSourceMapping to reject a role lacking SQS read permissions with "
        f"InvalidParameterValueException, got {code!r}"
    )
    expected_message = (
        "The function execution role does not have permissions to call ReceiveMessage on SQS"
    )
    assert message == expected_message, (
        f"expected CreateEventSourceMapping's message {expected_message!r}, got {message!r}"
    )

    # Effect is absent: no event source mapping exists for this function/queue pair.
    mappings = lam.list_event_source_mappings(EventSourceArn=queue["arn"], FunctionName=bare_fn["name"])
    assert mappings["EventSourceMappings"] == [], (
        f"expected no event source mapping for {bare_fn['name']!r}, found "
        f"{mappings['EventSourceMappings']!r}"
    )

    # --- Positive control: a role with the required permissions succeeds.
    good_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "esm-perms": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                        "Resource": queue["arn"],
                    }
                ],
            }
        },
    )
    good_fn = _create_function(
        ctx,
        good_role_arn,
        code="def handler(event, context):\n    return {'ok': True}\n",
    )
    mapping = lam.create_event_source_mapping(
        EventSourceArn=queue["arn"], FunctionName=good_fn["name"], BatchSize=10
    )
    uuid = mapping["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    state = _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid)["State"],
        lambda s: s == "Enabled",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert state == "Enabled", f"expected the well-permissioned mapping to reach Enabled, got {state!r}"


_MANAGED_TAG_KEY = "sim2real:managed"


def _error(ctx, fn) -> tuple[str, str]:
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS is the strongest
    signal available (the target is over-permissive)."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    if isinstance(result, dict) and "UUID" in result:
        ctx.on_cleanup(lambda: ctx.client("lambda").delete_event_source_mapping(UUID=result["UUID"]))
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"}],
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
                Tags={_MANAGED_TAG_KEY: "true"},
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
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags={_MANAGED_TAG_KEY: "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
