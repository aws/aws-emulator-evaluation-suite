"""events-pipes-enrichment-stopped-pipe-consumes-nothing-and-start-drains-backlog."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-pipes-enrichment-stopped-pipe-consumes-nothing-and-start-drains-backlog"
GROUP = "lifecycle"
SERVICES = ["lambda", "pipes", "sqs"]

# Shared by both pipes. Every record it sees is audited with the queue it came from, so the audit
# queue shows whether the STOPPED pipe ever handed anything to the enrichment.
_ENRICH_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")

def handler(event, context):
    out = []
    for record in event:
        body = json.loads(record["body"])
        _sqs.send_message(QueueUrl=os.environ["AUDIT_URL"], MessageBody=json.dumps(
            {"seen": body["marker"], "from": record["eventSourceARN"]}))
        out.append({"marker": body["marker"], "enriched": True,
                    "from": record["eventSourceARN"]})
    return out
"""

_N = 5


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A STOPPED pipe consumes nothing (backlog intact, enrichment and target untouched) while a
    RUNNING twin delivers; StartPipe then drains the whole backlog through the enrichment.
    """
    sqs = ctx.client("sqs")
    pipes = ctx.client("pipes")
    src_stopped = _create_queue(ctx, VisibilityTimeout="60")
    tgt_stopped = _create_queue(ctx)
    src_twin = _create_queue(ctx, VisibilityTimeout="60")
    tgt_twin = _create_queue(ctx)
    audit = _create_queue(ctx)
    enrichment = _create_enrichment(ctx, _ENRICH_CODE, env={"AUDIT_URL": audit["url"]},
                                    send_to=[audit["arn"]])
    role_stopped = _create_pipe_role(ctx, source_arn=src_stopped["arn"],
                                     target_arns=[tgt_stopped["arn"]],
                                     function_arns=[enrichment["arn"]])
    role_twin = _create_pipe_role(ctx, source_arn=src_twin["arn"], target_arns=[tgt_twin["arn"]],
                                  function_arns=[enrichment["arn"]])
    stopped = _create_pipe(ctx, source=src_stopped["arn"], target=tgt_stopped["arn"],
                           role_arn=role_stopped["arn"], desired_state="STOPPED",
                           Enrichment=enrichment["arn"],
                           SourceParameters={"SqsQueueParameters": {"BatchSize": 1}})
    _create_pipe(ctx, source=src_twin["arn"], target=tgt_twin["arn"], role_arn=role_twin["arn"],
                 Enrichment=enrichment["arn"],
                 SourceParameters={"SqsQueueParameters": {"BatchSize": 1}})

    run_id = _xname(ctx, "bk")
    held = {f"{run_id}-held-{i}" for i in range(_N)}
    twin = {f"{run_id}-twin-{i}" for i in range(_N)}
    for url, markers in ((src_stopped["url"], held), (src_twin["url"], twin)):
        resp = sqs.send_message_batch(QueueUrl=url, Entries=[
            {"Id": str(i), "MessageBody": json.dumps({"marker": m})}
            for i, m in enumerate(sorted(markers))])
        assert not resp.get("Failed"), f"SendMessageBatch failed: {resp.get('Failed')!r}"

    # Barrier, not a timer: absence on the stopped side is inspected only after the twin delivers.
    twin_got = _drain_until(ctx, tgt_twin["url"], lambda got: twin <= {
        b.get("marker") for b in got if isinstance(b, dict)}, timeout_s=180,
        description="the running twin's enriched deliveries")
    assert all(b.get("enriched") is True for b in twin_got if isinstance(b, dict)), (
        f"twin deliveries were not enriched: {twin_got!r}"
    )

    # Effect absent while STOPPED: nothing delivered, nothing enriched, backlog intact.
    assert _drain_nowait(ctx, tgt_stopped["url"]) == [], "the STOPPED pipe delivered to its target"
    seen = [b for b in _drain_nowait_all(ctx, audit["url"]) if isinstance(b, dict)]
    leaked = [b for b in seen if b.get("seen") in held]
    assert leaked == [], f"the STOPPED pipe handed records to the enrichment: {leaked!r}"
    # The approximate counters are eventually consistent, so poll for the intact backlog; a pipe
    # that had consumed it would leave the visible count below _N and this would time out.
    _poll_until(lambda: sqs.get_queue_attributes(QueueUrl=src_stopped["url"], AttributeNames=[
        "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])["Attributes"],
        lambda a: int(a["ApproximateNumberOfMessages"]) == _N
        and int(a["ApproximateNumberOfMessagesNotVisible"]) == 0,
        timeout_s=45, description="the STOPPED pipe's source backlog intact (all visible)")

    # Resume: the whole backlog drains through the enrichment.
    pipes.start_pipe(Name=stopped)
    _poll_until(lambda: pipes.describe_pipe(Name=stopped).get("CurrentState"),
                lambda s: s == "RUNNING", timeout_s=180, interval_s=4,
                description=f"pipe {stopped} RUNNING")
    got = _drain_until(ctx, tgt_stopped["url"], lambda bodies: held <= {
        b.get("marker") for b in bodies if isinstance(b, dict)}, timeout_s=180,
        description="the drained backlog at the restarted pipe's target")
    bodies = [b for b in got if isinstance(b, dict)]
    # At-least-once delivery: compare marker sets, not counts.
    assert {b["marker"] for b in bodies} == held, (
        f"restarted pipe delivered {sorted(b.get('marker') for b in bodies)!r}, sent {sorted(held)!r}"
    )
    assert all(b.get("enriched") is True and b.get("from") == src_stopped["arn"] for b in bodies), (
        f"backlog reached the target without passing the enrichment: {bodies!r}"
    )


def _drain_nowait(ctx: Any, url: str) -> list[Any]:
    """One long poll pass: receive-and-delete whatever is on the queue now."""
    sqs = ctx.client("sqs")
    got: list[Any] = []
    for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10,
                                 WaitTimeSeconds=5).get("Messages", []):
        got.append(_parse(m["Body"]))
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
    return got


def _drain_nowait_all(ctx: Any, url: str) -> list[Any]:
    """Receive-and-delete until a long poll comes back empty."""
    got: list[Any] = []
    while True:
        batch = _drain_nowait(ctx, url)
        if not batch:
            return got
        got.extend(batch)


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
