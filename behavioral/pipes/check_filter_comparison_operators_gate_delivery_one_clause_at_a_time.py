"""filter-comparison-operators-gate-delivery-one-clause-at-a-time."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "filter-comparison-operators-gate-delivery-one-clause-at-a-time"
GROUP = "server-side"
SERVICES = ["pipes"]


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Pipes' FilterCriteria applies numeric, prefix, anything-but and exists:false, ANDed: the
    matching record is delivered once and each near-miss differing in one field is not delivered.
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html"""
    pipes_client = ctx.client("pipes")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    source = _create_queue(ctx, VisibilityTimeout="60")
    target = _create_queue(ctx)
    role = _create_pipe_role(
        ctx,
        _sqs_read_statements(source["arn"])
        + [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target["arn"]}],
    )
    assert account in source["arn"], (
        f"source queue ARN {source['arn']!r} must belong to the STS-asserted account {account!r}; "
        f"a mismatch means the harness is pointed somewhere unexpected"
    )

    # ONE Pattern object, four clauses. Clauses inside a single Pattern are ANDed, so every clause
    # must hold for the record to pass. (Multiple *Filters* would be ORed -- a different check.)
    pattern = {
        "body": {
            "severity": [{"numeric": [">=", 500]}],
            "stage": [{"prefix": "prod-"}],
            "team": [{"anything-but": ["ignore-me"]}],
            "suppress": [{"exists": False}],
        }
    }

    run_id = _xname(ctx, "op")
    control_marker = f"{run_id}-CONTROL"
    # Each near-miss is the control body with exactly one field changed.
    control_body = {
        "severity": 500,
        "stage": "prod-1",
        "team": "core",
        "marker": control_marker,
    }
    near_misses: dict[str, dict[str, Any]] = {
        "numeric": {**control_body, "severity": 499, "marker": f"{run_id}-NUMERIC"},
        "prefix": {**control_body, "stage": "staging-1", "marker": f"{run_id}-PREFIX"},
        "anything-but": {**control_body, "team": "ignore-me", "marker": f"{run_id}-ANYTHINGBUT"},
        "exists": {**control_body, "suppress": "yes", "marker": f"{run_id}-EXISTS"},
    }

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
    params = pipes_client.describe_pipe(Name=pipe)["SourceParameters"]
    assert "FilterCriteria" in params, (
        f"pipe {pipe!r} was created with a FilterCriteria but DescribePipe reports none at all: "
        f"{params!r}. A target that drops the filter cannot be graded on how it evaluates it."
    )
    stored = json.loads(params["FilterCriteria"]["Filters"][0]["Pattern"])
    assert stored == pattern, (
        f"pipe {pipe!r} did not store the comparison-operator pattern it was given; "
        f"expected {pattern!r}, DescribePipe returned {stored!r}"
    )

    # All five are sent together, so the control proves the wiring is live in the same window.
    for body in [control_body, *near_misses.values()]:
        sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps(body))

    _await_source_fully_processed(
        ctx,
        source["url"],
        timeout_s=420.0,
        why=f"all 5 records handed to pipe {pipe!r} (1 match + 4 single-clause near-misses)",
    )

    received, latency = _await_marker(
        ctx,
        target["url"],
        control_marker,
        timeout_s=180.0,
        description=(
            f"the fully-matching control record {control_marker!r} reaching the target of pipe "
            f"{pipe!r}; without it every absence below would be vacuous"
        ),
    )
    # Hold for 3x the control's measured latency on top of the drained-source barrier.
    received.extend(_drain(ctx, target["url"], window_s=max(20.0, 3.0 * latency)))

    bodies = [m["Body"] for m in received]
    delivered_control = [b for b in bodies if control_marker in b]
    assert len(delivered_control) == 1, (
        f"the matching record must be delivered exactly once: expected 1 target message carrying "
        f"{control_marker!r}, got {len(delivered_control)} out of {len(bodies)} target messages "
        f"{bodies!r}"
    )

    leaked = {
        clause: body["marker"]
        for clause, body in near_misses.items()
        if any(body["marker"] in b for b in bodies)
    }
    assert leaked == {}, (
        f"pipe {pipe!r} delivered {len(leaked)} record(s) that violate exactly one filter clause "
        f"each: {leaked!r}. Expected none; the four clauses are numeric>=500, prefix 'prod-', "
        f"anything-but 'ignore-me', exists:false on 'suppress'. Control latency was "
        f"{latency:.1f}s and the source was already fully drained, so this is not a timing effect."
    )

_PREFIX = "sim2real-pipesgap-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result) is truthy; return that result. Raises on timeout."""
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

    Pipes assumes the role at CreatePipe time, so only the assume-role/PassRole propagation
    errors are retried; any other rejection is raised.
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
    absence window.
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

    Pipes removes filtered-out SQS messages from the queue too, so an empty source means every
    record has already been through the filter.
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
