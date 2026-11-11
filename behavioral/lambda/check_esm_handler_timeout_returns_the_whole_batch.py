"""esm-handler-timeout-returns-the-whole-batch."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "esm-handler-timeout-returns-the-whole-batch"

GROUP = "event-source-mapping"

SERVICES = ["lambda"]

_N = 2
_VISIBILITY_S = 10
_MAX_RECEIVE = 2
_FUNCTION_TIMEOUT_S = 3

# Runs INSIDE the deployed function. The slow arm sleeps past the function's own configured
# Timeout, so the invocation is killed by Lambda rather than returning anything: it prints ENTER and
# can never print DONE. The sleep is the SUBJECT of this check, not a stand-in for a wait -- it is
# how the timeout is provoked, and it is sized off the function's configured Timeout rather than off
# any observed latency.
_HANDLER = """
import json
import os
import time

def lambda_handler(event, context):
    records = event.get("Records", [])
    slow = any(r.get("eventSourceARN") == os.environ["SLOW_ARM_QUEUE_ARN"] for r in records)
    for rec in records:
        print("ENTER " + json.dumps({
            "body": rec["body"],
            "rc": int(rec.get("attributes", {}).get("ApproximateReceiveCount", "0")),
            "arm": "slow" if slow else "control",
        }, sort_keys=True))
    if slow:
        time.sleep(int(os.environ["OVERRUN_S"]))
    ret = {"done": [r["body"] for r in records], "arm": "slow" if slow else "control"}
    print("DONE " + json.dumps(ret, sort_keys=True))
    return ret
"""


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An invocation killed by the function's own Timeout returns its whole batch: the bodies are
    entered but never completed, redelivered and finally redriven to the DLQ, while the same code
    returning in time on identical wiring has its batch deleted.
    """
    sqs = ctx.client("sqs")

    slow_dlq = _create_queue(ctx)
    slow_q = _create_queue(
        ctx,
        VisibilityTimeout=str(_VISIBILITY_S),
        RedrivePolicy=json.dumps(
            {"deadLetterTargetArn": slow_dlq["arn"], "maxReceiveCount": _MAX_RECEIVE}
        ),
    )
    control_dlq = _create_queue(ctx)
    control_q = _create_queue(
        ctx,
        VisibilityTimeout=str(_VISIBILITY_S),
        RedrivePolicy=json.dumps(
            {"deadLetterTargetArn": control_dlq["arn"], "maxReceiveCount": _MAX_RECEIVE}
        ),
    )

    fn = _create_lambda(
        ctx,
        _HANDLER,
        permissions=[{"Action": _POLL_ACTIONS, "Resource": [slow_q["arn"], control_q["arn"]]}],
        env={
            "SLOW_ARM_QUEUE_ARN": slow_q["arn"],
            "OVERRUN_S": str(_FUNCTION_TIMEOUT_S * 4),
        },
        timeout=_FUNCTION_TIMEOUT_S,
    )
    configured = ctx.client("lambda").get_function_configuration(FunctionName=fn["name"])["Timeout"]
    assert configured == _FUNCTION_TIMEOUT_S, (
        f"the function's configured Timeout is {configured!r}, not {_FUNCTION_TIMEOUT_S}; the slow "
        "arm's sleep is sized off this value and would not provoke a timeout"
    )

    mappings = [
        _create_esm(
            ctx,
            EventSourceArn=queue["arn"],
            FunctionName=fn["name"],
            BatchSize=10,
            Enabled=True,
        )
        for queue in (slow_q, control_q)
    ]
    for esm in mappings:
        _wait_esm_state(ctx, esm["UUID"], "Enabled")

    since_ms = int(time.time() * 1000) - 5_000
    run_id = ctx.unique_name("payload-")
    slow_bodies = [f"{run_id}-slow-{i}" for i in range(_N)]
    control_bodies = [f"{run_id}-control-{i}" for i in range(_N)]
    for body in slow_bodies:
        sqs.send_message(QueueUrl=slow_q["url"], MessageBody=body)
    for body in control_bodies:
        sqs.send_message(QueueUrl=control_q["url"], MessageBody=body)

    wanted = set(slow_bodies) | set(control_bodies)
    entered_lines = _await_lines(
        ctx,
        fn["name"],
        since_ms,
        "ENTER ",
        lambda ls: {r["body"] for r in _records(ls, "ENTER ")} >= wanted,
        timeout_s=180.0,
    )
    entered = {r["body"] for r in _records(entered_lines, "ENTER ")}
    assert entered >= wanted, (
        "both mappings must deliver before either arm can be judged; the handler only ever entered "
        f"with {sorted(entered)!r}, missing {sorted(wanted - entered)!r}"
    )

    # Slow arm: delivered, never completed, returned, then redriven.
    redelivered = _await_lines(
        ctx,
        fn["name"],
        since_ms,
        "ENTER ",
        lambda ls: {r["body"] for r in _records(ls, "ENTER ") if r["rc"] > 1} >= set(slow_bodies),
        timeout_s=150.0,
    )
    retried = {r["body"] for r in _records(redelivered, "ENTER ") if r["rc"] > 1}
    not_retried = sorted(set(slow_bodies) - retried)
    assert not not_retried, (
        f"a batch whose invocation was killed by the function Timeout was not returned to the "
        f"queue: {not_retried!r} were never redelivered. A timed-out invocation produces no error "
        f"response, so deleting its batch is the over-permissive reading. Redelivered: "
        f"{sorted(retried)!r}"
    )

    slow_dead = _await_drain(
        ctx,
        slow_dlq["url"],
        lambda ms: {m["Body"] for m in ms} >= set(slow_bodies),
        timeout_s=150.0,
    )
    slow_dead_bodies = {m["Body"] for m in slow_dead}
    assert slow_dead_bodies >= set(slow_bodies), (
        f"the timed-out arm's messages never reached the redrive target: expected all of "
        f"{sorted(slow_bodies)!r} after maxReceiveCount={_MAX_RECEIVE} killed batches, saw "
        f"{sorted(slow_dead_bodies)!r} -- so they were neither retried to exhaustion nor completed"
    )
    completed = {b for r in _records(_handler_lines(ctx, fn["name"], since_ms, "DONE "), "DONE ") for b in r["done"]}
    wrongly_done = sorted(completed & set(slow_bodies))
    assert not wrongly_done, (
        f"the slow arm reached its DONE line for {wrongly_done!r}, so the invocation was NOT killed "
        f"by the {_FUNCTION_TIMEOUT_S}s Timeout and this check is measuring the wrong failure mode"
    )
    s_visible, s_in_flight = _await_counts(ctx, slow_q["url"], (0, 0), timeout_s=90.0)
    assert (s_visible, s_in_flight) == (0, 0), (
        f"the timed-out arm's source queue still holds visible={s_visible}, "
        f"in_flight={s_in_flight} after every message was redriven"
    )

    # Control arm: the same code, returning in time, has its batch deleted.
    control_done = _await_lines(
        ctx,
        fn["name"],
        since_ms,
        "DONE ",
        lambda ls: {b for r in _records(ls, "DONE ") for b in r["done"]} >= set(control_bodies),
        timeout_s=120.0,
    )
    control_completed = {b for r in _records(control_done, "DONE ") for b in r["done"]}
    assert control_completed >= set(control_bodies), (
        f"control: the identical handler must complete for the fast arm, but only "
        f"{sorted(control_completed)!r} ever reached DONE; without a completing control the slow "
        "arm's non-completion is unattributable"
    )
    c_visible, c_in_flight = _await_counts(ctx, control_q["url"], (0, 0), timeout_s=150.0)
    assert (c_visible, c_in_flight) == (0, 0), (
        f"control: a completed batch must be deleted, but the control queue still holds "
        f"visible={c_visible}, in_flight={c_in_flight}. Without this leg the slow arm above proves "
        "only that this wiring never deletes anything."
    )
    # The control source queue already reads empty, so no message is left that could still be
    # redriven; a short window suffices to read anything that was.
    control_dead = _drain(ctx, control_dlq["url"], window_s=3.0)
    assert control_dead == [], (
        "control: a batch the handler completed was redriven anyway -- "
        f"{[m['Body'] for m in control_dead]!r}"
    )
    cd_visible, cd_in_flight = _queue_counts(ctx, control_dlq["url"])
    assert (cd_visible, cd_in_flight) == (0, 0), (
        f"control: the control arm's redrive target reports visible={cd_visible}, "
        f"in_flight={cd_in_flight}; nothing from a completed batch may be dead-lettered"
    )

_PREFIX = "sim2real-esm-"

_POLL_ACTIONS = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]


def _resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": _PREFIX.rstrip("-")}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition", ctx=None
):
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_queue(ctx, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, Attributes=dict(attrs), tags=_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"name": name, "url": url, "arn": arn}


def _queue_counts(ctx, url: str) -> tuple[int, int]:
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]
    return (
        int(attrs.get("ApproximateNumberOfMessages", "-1")),
        int(attrs.get("ApproximateNumberOfMessagesNotVisible", "-1")),
    )


def _await_counts(ctx, url: str, want: tuple[int, int], *, timeout_s=120.0) -> tuple[int, int]:
    """Poll the queue's depth until it reaches `want`, then return the LAST reading either way.
    The caller asserts, so a timeout reports the real numbers instead of raising a bare timeout."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = _queue_counts(ctx, url)
    while time.monotonic() < deadline:
        last = _queue_counts(ctx, url)
        if last == want:
            return last
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"queue depth to reach {want!r} (last {last!r}): the run budget ended first; not graded")
    return last


def _handler_lines(ctx, fn_name: str, since_ms: int, prefix: str) -> list[str]:
    """Every stdout line the handler emitted since `since_ms` that starts with `prefix`.

    Paginated; keyed on (eventId, line) so repeated polls do not double-count real redeliveries."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    found: dict[tuple[str, str], str] = {}
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, startTime=since_ms
        )
        for page in pages:
            for event in page.get("events", []):
                for raw in event.get("message", "").splitlines():
                    line = raw.strip()
                    if line.startswith(prefix):
                        found[(event["eventId"], line)] = line
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return list(found.values())


def _await_lines(ctx, fn_name: str, since_ms: int, prefix: str, predicate, *, timeout_s=180.0):
    """Poll the log group until predicate(lines) holds; return the last read either way."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    lines = _handler_lines(ctx, fn_name, since_ms, prefix)
    while time.monotonic() < deadline:
        lines = _handler_lines(ctx, fn_name, since_ms, prefix)
        if predicate(lines):
            return lines
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"handler {prefix.strip()} lines in {fn_name}'s log: the run budget ended first; not graded")
    return lines


def _records(lines: list[str], prefix: str) -> list[dict[str, Any]]:
    """Parse `PREFIX <json>` evidence lines structurally."""
    return [json.loads(line[len(prefix) :]) for line in lines]


def _create_role(ctx, inline_policy: dict[str, Any]) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
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
    iam.delete_role(RoleName=role_name)


def _reap_log_group(ctx, group: str, *, rounds=4, settle_s=4.0) -> None:
    """Delete the function's log group, re-deleting if a late-flushed stream recreates it.

    delete_function leaves /aws/lambda/<fn>; bounded rounds, raising if it never converges."""
    logs = ctx.client("logs")
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(settle_s)
        present = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(g["logGroupName"] == group for g in present):
            return
    raise RuntimeError(f"log group {group} reappeared after {rounds} delete rounds")


def _create_lambda(ctx, handler_code: str, permissions=None, env=None, timeout=30) -> dict[str, str]:
    """Create a Lambda whose execution role is scoped to `permissions` (logs always allowed).

    Teardown is registered so LIFO deletes the function, then reaps its log group, then the role."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        resource = perm["Resource"] if isinstance(perm["Resource"], list) else [perm["Resource"]]
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(ctx, {"Version": "2012-10-17", "Statement": statements})

    name = _xname(ctx, "fn")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))

    lam = ctx.client("lambda")
    code = textwrap.dedent(handler_code)
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role["arn"],
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    # IAM role propagation exposes no condition to poll -- no API reports that a fresh role has
    # become assumable -- so the bounded retry on the one error code it raises is what makes this
    # correct, and the sleep only makes it cheaper.
    deadline = time.monotonic() + _budget_s(ctx, 90)
    last: Exception | None = None
    arn = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(2)
    if arn is None and _budget_spent(ctx):
        raise TimeoutError("CreateFunction to accept the fresh role: the run budget ended first; not graded")
    assert arn is not None, f"CreateFunction never accepted the fresh role within 90s: {last!r}"
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=90.0,
        interval_s=1.0,
        description=f"Lambda {name} State=Active",
        ctx=ctx,
    )
    return {"name": name, "arn": arn}


def _create_esm(ctx, **kwargs: Any) -> dict[str, Any]:
    """CreateEventSourceMapping VALIDATES the execution role's sqs:ReceiveMessage grant, so it is
    refused until the fresh role has propagated. Bounded retry on that one code."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + _budget_s(ctx, 90)
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            esm = lam.create_event_source_mapping(**kwargs)
            uuid_ = esm["UUID"]
            ctx.on_cleanup(lambda u=uuid_: _delete_esm(ctx, u))
            return esm
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("CreateEventSourceMapping to accept the role: the run budget ended first; not graded")
    raise AssertionError(f"CreateEventSourceMapping never accepted the role within 90s: {last!r}")


def _delete_esm(ctx, uuid_: str) -> None:
    try:
        ctx.client("lambda").delete_event_source_mapping(UUID=uuid_)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_esm_state(ctx, uuid_: str, want: str, *, timeout_s=210.0) -> None:
    """Wait for the ESM to report `want`; asserting delivery before the poller starts is a race."""
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid_).get("State"),
        lambda s: s == want,
        timeout_s=timeout_s,
        interval_s=1.0,
        description=f"ESM {uuid_} State={want}",
        ctx=ctx,
    )


def _drain(ctx, url: str, *, window_s=20.0, max_total=25) -> list[dict[str, Any]]:
    """Long-poll a queue over a bounded window and return EVERY message seen, deleting as it goes.

    An empty return is only meaningful beside a positive observation elsewhere in the check."""
    sqs = ctx.client("sqs")
    seen: list[dict[str, Any]] = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline and len(seen) < max_total:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _await_drain(ctx, url: str, predicate, *, timeout_s=120.0) -> list[dict[str, Any]]:
    """Receive and delete messages until predicate(messages) holds; return everything seen."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        wait = min(2, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
        if predicate(seen):
            return seen
    if _budget_spent(ctx):
        raise TimeoutError("the expected messages on the queue: the run budget ended first; not graded")
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
