"""events-pipes-enrichment-sees-whole-batch-and-target-gets-its-single-result."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-pipes-enrichment-sees-whole-batch-and-target-gets-its-single-result"
GROUP = "batching"
SERVICES = ["lambda", "pipes", "sqs"]

# One aggregate item per invocation, whatever the batch size: the target should therefore receive
# one message per ENRICHMENT INVOCATION, not one per source record.
_ENRICH_CODE = """
import json

def handler(event, context):
    bodies = [json.loads(r["body"]) for r in event]
    return [{
        "batch_len": len(event),
        "markers": sorted(b["marker"] for b in bodies),
        "sum": sum(b["n"] for b in bodies),
    }]
"""

_N = 10


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """With BatchSize=10 and a batching window, the enrichment receives multi-record batches as one
    list and the target gets one consistent aggregate per batch, not one message per source record.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/pipes-batching-concurrency.html
    """
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")
    source = _create_queue(ctx, VisibilityTimeout="60")
    target = _create_queue(ctx)
    enrichment = _create_enrichment(ctx, _ENRICH_CODE)
    role = _create_pipe_role(ctx, source_arn=source["arn"], target_arns=[target["arn"]],
                             function_arns=[enrichment["arn"]])
    pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        desired_state="STOPPED",
        Enrichment=enrichment["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 10,
                                                 "MaximumBatchingWindowInSeconds": 20}},
    )

    # Enqueue the backlog while the pipe is STOPPED so batches form from records already present.
    run_id = _xname(ctx, "b")
    sent = {f"{run_id}-{i}": i + 1 for i in range(_N)}
    resp = sqs.send_message_batch(QueueUrl=source["url"], Entries=[
        {"Id": str(i), "MessageBody": json.dumps({"marker": m, "n": n})}
        for i, (m, n) in enumerate(sent.items())])
    assert not resp.get("Failed"), f"SendMessageBatch failed entries: {resp.get('Failed')!r}"
    _poll_until(lambda: sqs.get_queue_attributes(QueueUrl=source["url"], AttributeNames=[
        "ApproximateNumberOfMessages"])["Attributes"]["ApproximateNumberOfMessages"],
        lambda v: int(v) == _N, timeout_s=60, description="the ten-record backlog on the source")

    pipes.start_pipe(Name=pipe)
    got = _drain_until(ctx, target["url"], lambda bodies: set(sent) <= {
        m for b in bodies if isinstance(b, dict) for m in b.get("markers", [])},
        timeout_s=200, description="aggregates covering all ten records at the target")

    # The poller may split the records across several batches, so the grouping is not pinned;
    # markers are compared as sets to tolerate redelivery.
    aggregates = [b for b in got if isinstance(b, dict) and "batch_len" in b]
    assert len(aggregates) == len(got), f"a target message was not an enrichment aggregate: {got!r}"
    for agg in aggregates:
        assert agg["batch_len"] == len(agg["markers"]), (
            f"enrichment output inconsistent with its own input batch: {agg!r}"
        )
        assert agg["sum"] == sum(sent[m] for m in agg["markers"]), (
            f"computed sum does not match the records in the batch: {agg!r}"
        )
    covered = {m for a in aggregates for m in a["markers"]}
    assert covered == set(sent), (
        f"markers delivered {sorted(covered)!r} != markers sent {sorted(sent)!r}"
    )
    sizes = sorted(a["batch_len"] for a in aggregates)
    assert max(sizes) > 1, (
        f"BatchSize=10 with a backlog of {_N}: every enrichment invocation saw one record "
        f"(batch sizes {sizes!r})"
    )
    assert len(aggregates) < _N, (
        f"{len(aggregates)} target messages for {_N} source records: the target was driven per "
        f"source record, not by the enrichment's per-batch result (batch sizes {sizes!r})"
    )


_PREFIX = "sim2real-xsvc-"
_RES_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0,
                description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last observed {last!r}")


def _create_queue(ctx: Any, **attrs: str) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"), Attributes=dict(attrs),
                           tags=dict(_RES_TAGS))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_role(ctx: Any, service: str, statements: list[dict]) -> dict[str, str]:
    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Path="/sim2real/",
                          Tags=[{"Key": k, "Value": v} for k, v in _RES_TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
    return {"name": name, "arn": arn}


def _delete_role(ctx: Any, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise RuntimeError(f"iam role {name}: {exc}") from exc


def _reap_log_group(ctx: Any, fn_name: str) -> None:
    """A buffered log stream can recreate /aws/lambda/<fn> after a delete, so reap in a loop and
    watch for reappearance; declare a leak rather than hang. Registered BEFORE create_function so
    LIFO runs it after the function is gone."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{fn_name}"
    for _ in range(4):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise RuntimeError(f"log group {group}: {exc}") from exc
        deadline = time.monotonic() + 8
        reappeared = False
        while time.monotonic() < deadline:
            found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
            if any(g["logGroupName"] == group for g in found):
                reappeared = True
                break
            time.sleep(2)
        if not reappeared:
            return
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _create_enrichment(ctx: Any, code: str, env: dict[str, str] | None = None,
                       send_to: list[str] | None = None) -> dict[str, str]:
    """A python Lambda used as the pipe's enrichment. Its role has NO logs permissions, so it
    cannot create a log group; the reap loop is still registered as a net."""
    statements = []
    if send_to:
        statements.append({"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": send_to})
    role = _create_role(ctx, "lambda.amazonaws.com", statements)
    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    kwargs: dict[str, Any] = {
        "FunctionName": name, "Runtime": "python3.12", "Role": role["arn"],
        "Handler": "index.handler", "Code": {"ZipFile": buf.getvalue()},
        "Timeout": 30, "MemorySize": 128, "Tags": dict(_RES_TAGS),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = lam.create_function(**kwargs)["FunctionArn"]
            break
        except ClientError as exc:
            # A just-created execution role is not yet assumable by Lambda (IAM propagation).
            if (exc.response["Error"]["Code"] == "InvalidParameterValueException"
                    and time.monotonic() < deadline):
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=name).get("State"),
                lambda s: s == "Active", timeout_s=90, description=f"lambda {name} Active")
    return {"name": name, "arn": arn}


def _create_pipe_role(ctx: Any, *, source_arn: str, target_arns: list[str],
                      function_arns: list[str]) -> dict[str, str]:
    return _create_role(ctx, "pipes.amazonaws.com", [
        {"Effect": "Allow",
         "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
         "Resource": source_arn},
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
        {"Effect": "Allow", "Action": ["lambda:InvokeFunction"], "Resource": function_arns},
    ])


def _delete_pipe(ctx: Any, name: str) -> None:
    pipes = ctx.client("pipes")
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(3)
    raise RuntimeError(f"pipe {name} still present 120s after DeletePipe")


def _create_pipe(ctx: Any, *, source: str, target: str, role_arn: str,
                 desired_state: str = "RUNNING", **extra: Any) -> str:
    """CreatePipe, retrying only through the pipes-role propagation window, then wait for the
    pipe to settle in `desired_state`. Teardown waits for the pipe to be gone."""
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    deadline = time.monotonic() + 60
    while True:
        try:
            pipes.create_pipe(Name=name, RoleArn=role_arn, Source=source, Target=target,
                              DesiredState=desired_state,
                              Tags=dict(_RES_TAGS), **extra)
            break
        except ClientError as exc:
            if (exc.response["Error"]["Code"] == "ValidationException"
                    and "role" in str(exc).lower() and time.monotonic() < deadline):
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_pipe(ctx, name))
    state = _poll_until(lambda: pipes.describe_pipe(Name=name), lambda d: d.get("CurrentState") in (
        desired_state, "CREATE_FAILED", "START_FAILED"), timeout_s=180, interval_s=4,
        description=f"pipe {name} {desired_state}")
    assert state["CurrentState"] == desired_state, (
        f"pipe {name} settled in {state['CurrentState']!r} ({state.get('StateReason')!r}), "
        f"expected {desired_state!r}"
    )
    return name


def _parse(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return body


def _drain_until(ctx: Any, url: str, done, *, timeout_s: float, description: str) -> list[Any]:
    """Receive-and-delete from `url` until done(bodies_so_far) is true; return every body read."""
    sqs = ctx.client("sqs")
    got: list[Any] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                     WaitTimeSeconds=5).get("Messages", []):
            got.append(_parse(m["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if done(got):
            return got
    raise AssertionError(f"{description} did not arrive within {timeout_s}s; read {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
