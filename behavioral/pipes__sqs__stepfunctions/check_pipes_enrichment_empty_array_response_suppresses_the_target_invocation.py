"""pipes-enrichment-empty-array-response-suppresses-the-target-invocation."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-enrichment-empty-array-response-suppresses-the-target-invocation"
GROUP = "data-transformation"
SERVICES = ["pipes", "stepfunctions", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe whose enrichment returns `[]` invokes no target, while a twin pipe on the same wiring
    delivers its enrichment's return value (not the source envelope) exactly once.
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/pipes-enrichment.html"""
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    target = _create_queue(ctx)
    assert account in target["arn"], (
        f"shared target ARN {target['arn']!r} must belong to the STS-asserted account {account!r}"
    )
    run_id = _xname(ctx, "enr")
    drop_marker = f"{run_id}-SUPPRESSED"
    echo_marker = f"{run_id}-ENRICHED"

    def _wire(definition: dict[str, Any], label: str) -> dict[str, Any]:
        source = _create_queue(ctx, VisibilityTimeout="60")
        sm = _create_express_state_machine(ctx, definition)
        role = _create_pipe_role(
            ctx,
            _sqs_read_statements(source["arn"])
            + [
                {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target["arn"]},
                # Which of the two Pipes calls for an EXPRESS enrichment is not documented.
                {
                    "Effect": "Allow",
                    "Action": ["states:StartSyncExecution", "states:StartExecution"],
                    "Resource": sm["arn"],
                },
            ],
        )
        pipe = _create_pipe(
            ctx,
            source=source["arn"],
            target=target["arn"],
            role_arn=role["arn"],
            Enrichment=sm["arn"],
            SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
        )
        return {"label": label, "source": source, "sm": sm, "pipe": pipe}

    # The suppressing enrichment: output is literally [].
    suppress = _wire(
        {"StartAt": "Drop", "States": {"Drop": {"Type": "Pass", "Result": [], "End": True}}},
        "empty-array-response",
    )
    # The twin: output is an object carrying the source body, so its arrival proves BOTH that the
    # target was invoked and that what reached it is the enrichment's return value.
    echo = _wire(
        {
            "StartAt": "Echo",
            "States": {
                "Echo": {"Type": "Pass", "Parameters": {"echo.$": "$[0].body"}, "End": True}
            },
        },
        "echo-response",
    )

    sqs.send_message(QueueUrl=suppress["source"]["url"], MessageBody=json.dumps({"m": drop_marker}))
    sqs.send_message(QueueUrl=echo["source"]["url"], MessageBody=json.dumps({"m": echo_marker}))

    for wiring in (suppress, echo):
        _await_source_fully_processed(
            ctx,
            wiring["source"]["url"],
            timeout_s=420.0,
            why=(
                f"the record handed to the {wiring['label']} pipe {wiring['pipe']!r}, whose "
                f"enrichment {wiring['sm']['name']!r} has already run"
            ),
        )

    received, latency = _await_marker(
        ctx,
        target["url"],
        echo_marker,
        timeout_s=300.0,
        description=(
            f"the echo enrichment's return value reaching the shared target via pipe "
            f"{echo['pipe']!r}; this is the twin control, and without it the suppression claim "
            f"would pass against a target that invokes no enrichment and no target at all"
        ),
    )
    received.extend(_drain(ctx, target["url"], window_s=max(15.0, 3.0 * latency)))
    bodies = [m["Body"] for m in received]

    # The twin must deliver the ENRICHMENT's output, not the source envelope Pipes would have
    # forwarded had there been no enrichment.
    enriched = [json.loads(b) for b in bodies if echo_marker in b]
    assert len(enriched) == 1, (
        f"the echo pipe {echo['pipe']!r} must deliver its enrichment's return value exactly once: "
        f"expected 1 target message carrying {echo_marker!r}, got {len(enriched)} of "
        f"{len(bodies)} messages {bodies!r}"
    )
    assert set(enriched[0]) == {"echo"}, (
        f"the target received something other than the enrichment's return value from pipe "
        f"{echo['pipe']!r}: expected exactly the key 'echo' produced by the Pass state, got "
        f"{enriched[0]!r}. A source envelope here (messageId/eventSourceARN/body) means the "
        f"enrichment output was discarded and the raw record forwarded instead."
    )
    assert json.loads(enriched[0]["echo"]) == {"m": echo_marker}, (
        f"the echo enrichment was not handed the source record's body: expected "
        f"{{'m': {echo_marker!r}}}, the delivered value was {enriched[0]['echo']!r}"
    )

    assert not any(drop_marker in b for b in bodies), (
        f"pipe {suppress['pipe']!r} delivered {drop_marker!r} even though its enrichment "
        f"{suppress['sm']['name']!r} returned an empty array, which must suppress the target "
        f"invocation entirely. The twin pipe {echo['pipe']!r} delivered on the same wiring after "
        f"{latency:.1f}s and both source queues are fully drained, so this is neither a timing "
        f"effect nor a dead pipe. Target saw: {bodies!r}"
    )

_PREFIX = "sim2real-pipesgap-"
_MANAGED = {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefixed resource name."""
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED.items()]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result) is truthy; return that result, raise on timeout."""
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

    Retries only the assume-role/PassRole errors a just-created role hits during IAM propagation.
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
        # AttributeNames (not MessageSystemAttributeNames) works on older botocore versions too.
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

    Returns (everything received while waiting, seconds elapsed); the elapsed latency sizes the
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

    Pipes deletes a processed SQS record, so an empty source means every target call was issued.
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


def _create_express_state_machine(ctx, definition: dict[str, Any]) -> dict[str, str]:
    """Create an EXPRESS state machine (the only type Pipes accepts as an enrichment).

    Its role has no permissions because a Pass state needs none.
    """
    role = _create_role(ctx, "states.amazonaws.com")
    name = _xname(ctx, "sm")
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_state_machine(
        name=name,
        definition=json.dumps(definition),
        roleArn=role["arn"],
        type="EXPRESS",
        tags=[{"key": k, "value": v} for k, v in _MANAGED.items()],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: ctx.client("stepfunctions").delete_state_machine(stateMachineArn=arn))
    return {"name": name, "arn": arn}


def _create_role(ctx, trust_service: str) -> dict[str, str]:
    """A bare role trusting one AWS service principal, with no inline policy."""
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
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    return {"name": role_name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
