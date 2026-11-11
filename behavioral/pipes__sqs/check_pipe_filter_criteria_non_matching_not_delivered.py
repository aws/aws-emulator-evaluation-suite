"""pipe-filter-criteria-non-matching-not-delivered."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "pipe-filter-criteria-non-matching-not-delivered"

GROUP = "data-delivery"

SERVICES = ["pipes", "sqs"]

# The SQS record envelope Pipes puts on the target for a source message that carries message
# attributes.
_ENVELOPE_KEYS = {
    "attributes",
    "awsRegion",
    "body",
    "eventSource",
    "eventSourceARN",
    "md5OfBody",
    "md5OfMessageAttributes",
    "messageAttributes",
    "messageId",
    "receiptHandle",
}

_ENVELOPE_ATTRIBUTE_KEYS = {
    "ApproximateFirstReceiveTimestamp",
    "ApproximateReceiveCount",
    "SenderId",
    "SentTimestamp",
}


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge Pipes FilterCriteria non-match never reaches the target but is consumed from
    the source queue, while the matching control arrives as the SQS record envelope whose messageId
    and md5OfBody match what SendMessage returned.
    """
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")
    src = _create_queue(ctx, VisibilityTimeout="60")
    dst = _create_queue(ctx)

    role = _create_role(
        ctx,
        "pipes.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes",
                    ],
                    "Resource": src["arn"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["sqs:SendMessage"],
                    "Resource": dst["arn"],
                },
            ],
        },
    )

    pipe = _xname(ctx, "pipe")
    _create_pipe_with_retry(
        pipes,
        Name=pipe,
        RoleArn=role["arn"],
        Source=src["arn"],
        Target=dst["arn"],
        SourceParameters={
            "FilterCriteria": {
                "Filters": [{"Pattern": json.dumps({"body": {"kind": ["wanted"]}})}]
            },
            "SqsQueueParameters": {"BatchSize": 10},
        },
        Tags=_xsvc_resource_tags(),
    )
    ctx.on_cleanup(lambda: ctx.client("pipes").delete_pipe(Name=pipe))
    _poll_until(
        lambda: pipes.describe_pipe(Name=pipe).get("CurrentState"),
        lambda s: s == "RUNNING",
        timeout_s=240.0,
        interval_s=10.0,
        description=f"pipe {pipe} RUNNING",
    )

    # Message attributes are attached on purpose: they are what proves the envelope's
    # messageAttributes subtree really carries the SOURCE message's attributes (and that the
    # target message does not get them re-projected onto itself).
    bad_body = json.dumps({"kind": "unwanted", "marker": "suppressed"})
    good_body = json.dumps({"kind": "wanted", "marker": "control"})
    sent_bad = sqs.send_message(
        QueueUrl=src["url"],
        MessageBody=bad_body,
        MessageAttributes={"probe": {"DataType": "String", "StringValue": "attr-bad"}},
    )
    sent_good = sqs.send_message(
        QueueUrl=src["url"],
        MessageBody=good_body,
        MessageAttributes={"probe": {"DataType": "String", "StringValue": "attr-good"}},
    )

    ctl, others = _wait_for(
        ctx,
        dst["url"],
        lambda b: _inner(b).get("marker") == "control",
        timeout_s=240.0,
    )
    assert len(ctl) >= 1, (
        "control: the matching record must reach the pipe target -- a pipe that never delivers at "
        "all would make the suppression assertion vacuous"
    )

    # --- The delivered record is the SOURCE record, wrapped in the SQS envelope.
    env = _body(ctl[0])
    assert isinstance(env, dict), f"the target message body must be a JSON object, got {env!r}"
    assert set(env) == _ENVELOPE_KEYS, (
        f"the pipe must deliver the SQS record envelope, not the bare message body; expected keys "
        f"{sorted(_ENVELOPE_KEYS)}, got {sorted(env)}"
    )
    assert env["body"] == good_body, (
        f"the envelope's body is the source body VERBATIM as a string (not re-serialised, not "
        f"parsed into an object), expected {good_body!r}, got {env['body']!r}"
    )
    assert env["messageId"] == sent_good["MessageId"], (
        f"the envelope must carry the SOURCE message's id {sent_good['MessageId']!r} -- an id the "
        f"pipe minted itself would mean the target record is a copy and not the record; got "
        f"{env['messageId']!r}"
    )
    assert env["md5OfBody"] == sent_good["MD5OfMessageBody"], (
        f"md5OfBody must equal the MD5 SendMessage reported for the source body "
        f"({sent_good['MD5OfMessageBody']!r}), got {env['md5OfBody']!r}"
    )
    assert env["eventSource"] == "aws:sqs", (
        f"the envelope must name the source service as aws:sqs, got {env['eventSource']!r}"
    )
    assert env["eventSourceARN"] == src["arn"], (
        f"the envelope must name the SOURCE queue {src['arn']!r}, got {env['eventSourceARN']!r} -- "
        f"naming the target here is a mistake an emulator makes when it builds the envelope at the "
        f"delivery end instead of the polling end"
    )
    assert env["awsRegion"] == ctx.region, (
        f"expected awsRegion {ctx.region!r}, got {env['awsRegion']!r}"
    )
    assert env["messageAttributes"]["probe"]["stringValue"] == "attr-good", (
        f"the source message attribute must survive inside the envelope, got "
        f"{env['messageAttributes']!r}"
    )
    assert env["messageAttributes"]["probe"]["dataType"] == "String", (
        f"envelope message attributes are lowercase-keyed (dataType/stringValue), not the SQS "
        f"API's DataType/StringValue, got {sorted(env['messageAttributes']['probe'])}"
    )
    assert env["md5OfMessageAttributes"] == sent_good["MD5OfMessageAttributes"], (
        f"md5OfMessageAttributes must equal the MD5 SendMessage reported "
        f"({sent_good['MD5OfMessageAttributes']!r}), got {env['md5OfMessageAttributes']!r}"
    )
    assert set(env["attributes"]) == _ENVELOPE_ATTRIBUTE_KEYS, (
        f"expected exactly the four SQS system attributes {sorted(_ENVELOPE_ATTRIBUTE_KEYS)}, got "
        f"{sorted(env['attributes'])}"
    )
    assert env["attributes"]["ApproximateReceiveCount"] == "1", (
        f"the pipe received the record once, so ApproximateReceiveCount is the STRING \"1\", got "
        f"{env['attributes']['ApproximateReceiveCount']!r}"
    )
    assert "MessageAttributes" not in ctl[0], (
        f"the source's attributes belong inside the envelope only; the target message must not "
        f"carry MessageAttributes of its own, got {ctl[0].get('MessageAttributes')!r}"
    )

    # --- The non-matching record never reaches the target.
    others = others + _collect(ctx, dst["url"], window_s=45.0)
    leaked = [_inner(_body(m)) for m in others]
    bad = [b for b in leaked if b.get("marker") == "suppressed"]
    assert bad == [], (
        f"the pipe's FilterCriteria let {len(bad)} non-matching record(s) through to the target: "
        f"{bad}"
    )
    # The same negative pinned by identity rather than by payload: the suppressed record's own
    # messageId must never appear at the target, whatever shape it were delivered in.
    delivered_ids = {
        _body(m).get("messageId") for m in ([ctl[0]] + others) if isinstance(_body(m), dict)
    }
    assert sent_bad["MessageId"] not in delivered_ids, (
        f"the suppressed record {sent_bad['MessageId']!r} reached the target: {delivered_ids}"
    )
    # Anything else that arrived may only be an at-least-once redelivery of the matching record.
    assert all(b.get("marker") == "control" for b in leaked), (
        f"the target received records that are neither the matching one nor a redelivery of it: "
        f"{leaked}"
    )

    attrs = _queue_depth_zero(ctx, src["url"], timeout_s=180.0)
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"the filtered-out record was not consumed from the pipe source queue: {attrs}"
    )


# ===== helpers (self-contained) =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _body(msg: dict):
    """Parse an SQS message body as JSON, falling back to the raw string."""
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _inner(parsed):
    """The ORIGINAL source body, parsed, out of whatever the pipe put on the target queue.

    Real Pipes delivers the SQS record envelope with the source body as a string under ``body``
    (the envelope keys are pinned in _ENVELOPE_KEYS above), so that is unwrapped here. An emulator that
    forwards the bare body instead is deliberately still recognised: the check then reaches the
    envelope assertions and fails with "expected keys [...] got [...]" instead of timing out on
    "the matching record never arrived", which says nothing about what went wrong."""
    if isinstance(parsed, dict):
        if isinstance(parsed.get("body"), str):
            try:
                inner = json.loads(parsed["body"])
            except (json.JSONDecodeError, ValueError):
                return {}
            return inner if isinstance(inner, dict) else {}
        return parsed
    return {}


def _collect(ctx, queue_url, *, window_s=30.0, max_total=10, keep=False):
    """Drain a queue over a bounded window with long-polling ReceiveMessage(MaxNumberOfMessages=10)
    and return EVERY message seen. Never raises and never swallows an assertion.

    This is the NEGATIVE observable. An empty return is only meaningful once a positive control
    has already been observed elsewhere in the check -- that is what proves enough wall-clock and
    enough propagation elapsed for a delivery to have happened if the emulator were going to make
    one. Used alone it would pass against an emulator that delivers nothing at all."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=wait,
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            if not keep:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    return seen


def _wait_for(ctx, queue_url, predicate, *, timeout_s=60.0):
    """Poll a queue until a message whose parsed body satisfies predicate() arrives.
    Returns (matched, others) -- every non-matching message seen along the way is returned too so
    the caller can assert on leakage instead of silently discarding it."""
    matched: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        for msg in _collect(ctx, queue_url, window_s=min(8.0, timeout_s)):
            (matched if predicate(_body(msg)) else others).append(msg)
    return matched, others


def _queue_depth_zero(ctx, queue_url, *, timeout_s=90.0):
    """Poll until the queue reports zero visible AND zero in-flight messages.
    ApproximateNumberOfMessages is eventually consistent, hence the poll rather than one read."""
    sqs = ctx.client("sqs")

    def probe():
        return sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
            ],
        )["Attributes"]

    return _poll_until(
        probe,
        lambda a: (
            a.get("ApproximateNumberOfMessages") == "0"
            and a.get("ApproximateNumberOfMessagesNotVisible") == "0"
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"{queue_url} drained to zero",
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _create_pipe_with_retry(pipes_client, *, timeout_s: float = 60.0, **kwargs: Any) -> dict:
    """create_pipe, retried past IAM role trust/permission propagation lag.

    A freshly created role is not always immediately assumable by pipes.amazonaws.com; retry only
    the specific transient codes that mean "not yet propagated", never a genuine rejection."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return pipes_client.create_pipe(**kwargs)
        except ClientError as e:
            msg = str(e)
            if (
                "cannot be assumed" in msg
                or "not authorized to perform: iam:PassRole" in msg
                or "ValidationException" in msg
            ):
                last_err = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(
        f"could not create pipe {kwargs.get('Name')!r} within {timeout_s}s "
        f"(IAM role propagation?): {last_err}"
    )


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
