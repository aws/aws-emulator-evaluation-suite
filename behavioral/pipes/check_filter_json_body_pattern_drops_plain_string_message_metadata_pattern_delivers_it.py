"""filter-json-body-pattern-drops-plain-string-message-metadata-pattern-delivers-it."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-json-body-pattern-drops-plain-string-message-metadata-pattern-delivers-it"
GROUP = "server-side"
SERVICES = ["pipes"]


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe whose filter has a valid-JSON `body` clause drops a plain-string SQS message (format
    mismatch), while a twin pipe filtering only on messageAttributes delivers the same message.
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html"""
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account and account.isdigit(), (
        f"STS must report a numeric account id before any resource is created; got {account!r}"
    )

    run_id = _xname(ctx, "fmt")
    plain_marker = f"{run_id}-PLAIN"
    json_marker = f"{run_id}-JSON"
    # A body that is not JSON at all.
    plain_body = f"PLAIN-not-json-{plain_marker}"
    json_body = json.dumps({"kind": "order", "marker": json_marker})
    attrs = {"tier": {"DataType": "String", "StringValue": "gold"}}

    def _wire(pattern: dict[str, Any], label: str) -> dict[str, Any]:
        source = _create_queue(ctx, VisibilityTimeout="60")
        target = _create_queue(ctx)
        role = _create_pipe_role(
            ctx,
            _sqs_read_statements(source["arn"])
            + [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target["arn"]}],
        )
        pipe = _create_pipe(
            ctx,
            source=source["arn"],
            target=target["arn"],
            role_arn=role["arn"],
            SourceParameters={
                "SqsQueueParameters": {"BatchSize": 1},
                "FilterCriteria": {"Filters": [{"Pattern": json.dumps(pattern)}]},
            },
        )
        return {"label": label, "source": source, "target": target, "pipe": pipe}

    # P_json: a valid-JSON clause ON `body`. P_meta: metadata only, no `body` clause anywhere.
    p_json = _wire({"body": {"kind": ["order"]}}, "json-body-clause")
    p_meta = _wire({"messageAttributes": {"tier": {"stringValue": ["gold"]}}}, "metadata-only")

    for wiring in (p_json, p_meta):
        for body in (plain_body, json_body):
            sqs.send_message(
                QueueUrl=wiring["source"]["url"], MessageBody=body, MessageAttributes=attrs
            )

    for wiring in (p_json, p_meta):
        _await_source_fully_processed(
            ctx,
            wiring["source"]["url"],
            timeout_s=420.0,
            why=(
                f"both the plain-string and the JSON record handed to the {wiring['label']} pipe "
                f"{wiring['pipe']!r}"
            ),
        )

    # P_meta is the demonstrated delivery path: it must carry BOTH formats through.
    meta_seen, meta_latency = _await_marker(
        ctx,
        p_meta["target"]["url"],
        plain_marker,
        timeout_s=180.0,
        description=(
            f"the PLAIN-STRING record {plain_marker!r} reaching the target of the metadata-only "
            f"pipe {p_meta['pipe']!r}; a pattern with no `body` clause must skip the format check"
        ),
    )
    meta_seen.extend(_drain(ctx, p_meta["target"]["url"], window_s=max(15.0, 3.0 * meta_latency)))
    meta_bodies = [m["Body"] for m in meta_seen]
    assert any(json_marker in b for b in meta_bodies), (
        f"the metadata-only pipe {p_meta['pipe']!r} delivered the plain-string record but not the "
        f"JSON one ({json_marker!r}); both carry tier=gold and both must match a pattern that "
        f"only constrains messageAttributes. Target saw: {meta_bodies!r}"
    )

    # P_json: the JSON record is its own positive control; the plain string must have been dropped.
    json_seen, json_latency = _await_marker(
        ctx,
        p_json["target"]["url"],
        json_marker,
        timeout_s=180.0,
        description=(
            f"the matching JSON record {json_marker!r} reaching the target of the json-body-clause "
            f"pipe {p_json['pipe']!r}; without it the drop below would be vacuous"
        ),
    )
    json_seen.extend(_drain(ctx, p_json["target"]["url"], window_s=max(15.0, 3.0 * json_latency)))
    json_bodies = [m["Body"] for m in json_seen]
    assert not any(plain_marker in b for b in json_bodies), (
        f"pipe {p_json['pipe']!r} has a VALID-JSON clause on `body` and still delivered the "
        f"PLAIN-STRING record {plain_marker!r}, which EventBridge must drop on format mismatch. "
        f"The twin pipe {p_meta['pipe']!r} delivered that same plain string after "
        f"{meta_latency:.1f}s, so the record is deliverable and this is not a timing effect. "
        f"json-body-clause target saw: {json_bodies!r}"
    )

# ===== helpers =====
_PREFIX = "sim2real-pipesgap-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name so any leftover can be found by tag or prefix."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result) is truthy; return that result. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        if interval_s > 0:
            time.sleep(interval_s)
    raise AssertionError(
        f"{description}: not satisfied within {timeout_s}s. Last observed value: {last!r}"
    )


def _create_queue(ctx, *, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create a tagged SQS queue, register its teardown, and return {name,url,arn}."""
    sqs = ctx.client("sqs")
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=dict(_MANAGED)
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"name": name, "url": url, "arn": arn}


def _sqs_read_statements(source_arn: str) -> list[dict[str, Any]]:
    return [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        }
    ]


def _create_pipe_role(ctx, statements: list[dict[str, Any]]) -> dict[str, str]:
    """Create the pipe execution role (trusts pipes.amazonaws.com) carrying one inline policy."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    policy_name = "pipe-inline"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    _put_role_policy(ctx, role_name, policy_name, statements)
    return {"name": role_name, "arn": arn, "policy": policy_name}


def _put_role_policy(
    ctx, role_name: str, policy_name: str, statements: list[dict[str, Any]]
) -> None:
    ctx.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _delete_role(ctx, role_name: str) -> None:
    """Teardown: an IAM role cannot be deleted while it still holds inline policies."""
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_pipe(
    ctx,
    *,
    source: str,
    target: str,
    role_arn: str,
    wait_for: str = "RUNNING",
    timeout_s: float = 300.0,
    **extra: Any,
) -> str:
    """Create a pipe, wait for CurrentState == wait_for, and return its name.

    Pipes assumes the execution role at CreatePipe time, so a role created seconds earlier can
    lose the IAM propagation race; only the assume-role/PassRole messages are retried.
    """
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 10.0)))
    while True:
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState="RUNNING",
                Tags=dict(_MANAGED),
                **extra,
            )
            break
        except ClientError as exc:
            text = str(exc)
            if "cannot be assumed" not in text and "iam:PassRole" not in text:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"pipe {name!r} could not be created: EventBridge Pipes never managed to assume the "
                    f"freshly created execution role {role_arn!r} within 60 s. Last error: {exc!r}"
                ) from exc
            time.sleep(2)
    ctx.on_cleanup(lambda: _delete_pipe(ctx, name))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name)["CurrentState"],
        lambda s: s == wait_for,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=(
            f"pipe {name!r} reaching CurrentState=={wait_for!r} after CreatePipe (a pipe that "
            f"parks in CREATING or reaches CREATE_FAILED never polls its source)"
        ),
    )
    return name


def _delete_pipe(ctx, name: str) -> None:
    """Teardown: DeletePipe is refused with ConflictException while the pipe is transitioning."""
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + 45.0
    while True:
        try:
            pipes.delete_pipe(Name=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)


def _receive(ctx, queue_url: str, *, attribute_names: list[str] | None = None) -> list[dict]:
    """One bounded long-poll receive; deletes what it takes so nothing is counted twice."""
    sqs = ctx.client("sqs")
    kwargs: dict[str, Any] = {
        "QueueUrl": queue_url,
        "MaxNumberOfMessages": 10,
        "WaitTimeSeconds": 5,
    }
    if attribute_names is not None:
        # AttributeNames (not MessageSystemAttributeNames) works across botocore versions.
        kwargs["AttributeNames"] = attribute_names
    resp = sqs.receive_message(**kwargs)
    # SQS omits "Messages" entirely on an empty receive.
    msgs = resp["Messages"] if "Messages" in resp else []
    out = []
    for msg in msgs:
        out.append(msg)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain(ctx, queue_url: str, *, window_s: float) -> list[dict]:
    """Receive and delete everything that shows up on a queue inside a bounded window."""
    got: list[dict] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        got.extend(_receive(ctx, queue_url))
    return got


def _await_marker(
    ctx, queue_url: str, marker: str, *, timeout_s: float, description: str
) -> tuple[list[dict], float]:
    """Long-poll a queue until a message body containing `marker` arrives.

    Returns (everything received while waiting, seconds elapsed); the elapsed time sizes the
    absence window instead of a guessed sleep.
    """
    started = time.monotonic()
    got: list[dict] = []

    def _pull() -> list[dict]:
        got.extend(_receive(ctx, queue_url))
        return got

    _poll_until(
        _pull,
        lambda msgs: any(marker in m["Body"] for m in msgs),
        timeout_s=timeout_s,
        interval_s=0.0,
        description=description,
    )
    return got, time.monotonic() - started


def _outstanding(ctx, queue_url: str) -> int:
    """Messages the source queue still owns: visible plus in flight."""
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(
        attrs["ApproximateNumberOfMessagesNotVisible"]
    )


def _await_source_fully_processed(ctx, queue_url: str, *, timeout_s: float, why: str) -> None:
    """Wait until the source queue holds nothing, visible or in flight.

    Pipes removes an SQS message from the source once processed, including one the filter dropped,
    so an empty source means every delivery that will be issued has been issued.
    """
    _poll_until(
        lambda: _outstanding(ctx, queue_url),
        lambda n: n == 0,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=(
            f"source queue {queue_url} draining to zero outstanding records ({why}); a non-zero "
            f"residue means the pipe never consumed the records, so no absence claim is possible"
        ),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
