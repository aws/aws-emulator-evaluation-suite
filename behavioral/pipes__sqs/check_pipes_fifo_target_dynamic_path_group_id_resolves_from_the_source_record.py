"""pipes-fifo-target-dynamic-path-group-id-resolves-from-the-source-record."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-fifo-target-dynamic-path-group-id-resolves-from-the-source-record"
GROUP = "data-transformation"
SERVICES = ["pipes", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FIFO target's MessageGroupId given as the dynamic path "$.body.tenant" resolves per record
    from the SOURCE event, though the InputTemplate removed `tenant` from the delivered body; both
    the group and deduplication ids are read back at the consumer."""
    sqs = ctx.client("sqs")
    pipes_client = ctx.client("pipes")
    account = ctx.client("sts").get_caller_identity()["Account"]

    source = _create_queue(ctx, VisibilityTimeout="60")
    target = _create_queue(ctx, fifo=True)
    assert target["name"].endswith(".fifo"), (
        f"the target must be a FIFO queue for MessageGroupId to mean anything; got "
        f"{target['name']!r}"
    )
    role = _create_pipe_role(
        ctx,
        _sqs_read_statements(source["arn"])
        + [{"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target["arn"]}],
    )
    assert account in target["arn"], (
        f"FIFO target ARN {target['arn']!r} must belong to the STS-asserted account {account!r}"
    )

    run_id = _xname(ctx, "dyn")
    # `tenant` is deliberately NOT referenced by the InputTemplate, so it cannot survive into the
    # delivered body -- and is still demanded as the group id.
    records = [
        {"tenant": f"{run_id}-tenantA", "orderId": f"{run_id}-order1"},
        {"tenant": f"{run_id}-tenantB", "orderId": f"{run_id}-order2"},
    ]
    by_order = {r["orderId"]: r for r in records}

    pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        TargetParameters={
            "InputTemplate": '{"only": "<$.body.orderId>"}',
            "SqsQueueParameters": {
                "MessageGroupId": "$.body.tenant",
                "MessageDeduplicationId": "$.body.orderId",
            },
        },
    )
    target_params = pipes_client.describe_pipe(Name=pipe)["TargetParameters"]
    assert "SqsQueueParameters" in target_params, (
        f"pipe {pipe!r} was created with TargetParameters.SqsQueueParameters but DescribePipe "
        f"reports none: {target_params!r}"
    )
    stored = target_params["SqsQueueParameters"]
    assert stored["MessageGroupId"] == "$.body.tenant", (
        f"pipe {pipe!r} did not store the dynamic path it was given for MessageGroupId: expected "
        f"'$.body.tenant', DescribePipe returned {stored['MessageGroupId']!r}"
    )

    for record in records:
        sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps(record))

    # Every receive here asks for the SQS system attributes, because MessageGroupId and
    # MessageDeduplicationId are what the pipe had to compute -- they are not in the body.
    seen: dict[str, dict[str, Any]] = {}

    def _pull() -> dict[str, dict[str, Any]]:
        for msg in _receive(ctx, target["url"], attribute_names=["All"]):
            # Key on the orderId found in the delivered bytes rather than on a body field, so an
            # emulator that ignored the InputTemplate is diagnosed by the body assertion below
            # instead of dying here on a KeyError.
            matched = [order for order in by_order if order in msg["Body"]]
            assert len(matched) == 1, (
                f"a message on the FIFO target of pipe {pipe!r} matched {len(matched)} of the two "
                f"source orderIds {sorted(by_order)!r}, expected exactly 1: {msg['Body']!r}"
            )
            seen[matched[0]] = msg
        return seen

    _poll_until(
        _pull,
        lambda s: set(s) >= set(by_order),
        timeout_s=300.0,
        interval_s=0.0,
        description=(
            f"both records reaching the FIFO target of pipe {pipe!r} (the group-id comparison "
            f"needs two distinct groups to separate, so a single delivery is not enough). Expected "
            f"the `only` keys {sorted(by_order)!r}"
        ),
    )

    assert set(seen) == set(by_order), (
        f"pipe {pipe!r} must deliver exactly the two records, keyed by the InputTemplate's `only` "
        f"field: expected {sorted(by_order)!r}, target produced {sorted(seen)!r}"
    )
    groups: dict[str, str] = {}
    for order_id, msg in seen.items():
        source_record = by_order[order_id]
        body = json.loads(msg["Body"])
        # The InputTemplate really ran: the delivered body is the rendered object, nothing else.
        assert body == {"only": order_id}, (
            f"TargetParameters.InputTemplate did not render the delivered body for {order_id!r}: "
            f"expected {{'only': {order_id!r}}}, target delivered {body!r}"
        )
        # ... and `tenant` is provably absent from what the target received.
        assert source_record["tenant"] not in msg["Body"], (
            f"the delivered body for {order_id!r} still carries the source `tenant` value "
            f"{source_record['tenant']!r}, so the InputTemplate did not remove it and the claim "
            f"below would not distinguish source resolution from post-transform resolution: "
            f"{msg['Body']!r}"
        )
        attrs = msg["Attributes"]
        assert attrs["MessageGroupId"] == source_record["tenant"], (
            f"MessageGroupId for {order_id!r} must be resolved from the SOURCE record's "
            f"$.body.tenant: expected {source_record['tenant']!r}, the FIFO target reports "
            f"{attrs['MessageGroupId']!r} (delivered body was {msg['Body']!r}, which does not "
            f"contain tenant at all -- so this value can only have come from the source event)"
        )
        assert attrs["MessageDeduplicationId"] == order_id, (
            f"MessageDeduplicationId for {order_id!r} must be resolved from $.body.orderId: "
            f"expected {order_id!r}, the FIFO target reports "
            f"{attrs['MessageDeduplicationId']!r}"
        )
        groups[order_id] = attrs["MessageGroupId"]

    assert len(set(groups.values())) == 2, (
        f"the two records name different tenants, so they must land in two different FIFO ordering "
        f"groups; pipe {pipe!r} produced {groups!r}. A single group means the group id was a "
        f"constant, not a per-record path resolution."
    )

# ===== helpers =====
_PREFIX = "sim2real-pipesgap-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result) is truthy; return that result.

    RAISES on timeout and never returns its last value: a poll that returns on timeout turns
    "never converged" into whatever the last read happened to be.
    """
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
    lose the IAM propagation race. Only the assume-role/PassRole messages are retried: any other
    ValidationException is a permanent rejection and is raised at once.
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
        # AttributeNames (not MessageSystemAttributeNames) so this works on every botocore the
        # runner might carry.
        kwargs["AttributeNames"] = attribute_names
    resp = sqs.receive_message(**kwargs)
    # SQS OMITS "Messages" entirely on an empty receive; this is not a .get() default standing in
    # for an assertion subject, it is the wire shape of "nothing arrived".
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

    Returns (everything received while waiting, seconds elapsed). The elapsed time is the
    positive control's measured latency L on this exact wiring, which is what calibrates the
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

    Pipes DELETES an SQS record from the source once the pipe has processed it -- including a
    record the filter dropped. eb-pipes-event-filtering.html ("Filtering Amazon SQS messages"):
    "If an Amazon SQS message doesn't satisfy your filter criteria, EventBridge automatically
    removes the message from the queue." So an empty source proves every record has ALREADY been
    through filter -> enrichment -> target: whatever delivery was going to be issued has been
    issued. That makes the absence claim below structural rather than a wait, which is why no
    sleep appears anywhere in it.
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
