"""events-pipes-enrichment-failure-retains-source-record-and-withholds-target."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-pipes-enrichment-failure-retains-source-record-and-withholds-target"
GROUP = "error-propagation"
SERVICES = ["lambda", "pipes", "sqs"]

# Every invocation is audited (marker + the SQS receive count Pipes handed over) BEFORE the
# enrichment decides whether to throw, so the audit queue records each retry.
_ENRICH_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")

def handler(event, context):
    out = []
    for record in event:
        body = json.loads(record["body"])
        rc = int(record["attributes"]["ApproximateReceiveCount"])
        _sqs.send_message(QueueUrl=os.environ["AUDIT_URL"],
                          MessageBody=json.dumps({"seen": body["marker"], "rc": rc}))
        if body["marker"] == os.environ["FAIL_MARKER"]:
            raise RuntimeError("enrichment refuses " + body["marker"])
        out.append({"marker": body["marker"], "enriched": True, "rc": rc})
    return out
"""

_VISIBILITY_S = 10


# timing:real-time — visibility: 10 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A record whose enrichment throws is retried with a rising receive count and never reaches the
    target while a healthy record is delivered; once the enrichment stops throwing, the same record is
    delivered enriched with a receive count of at least two."""
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    source = _create_queue(ctx, VisibilityTimeout=str(_VISIBILITY_S))
    target = _create_queue(ctx)
    audit = _create_queue(ctx)
    boom = _xname(ctx, "boom")
    ok = _xname(ctx, "ok")
    enrichment = _create_enrichment(ctx, _ENRICH_CODE,
                                    env={"AUDIT_URL": audit["url"], "FAIL_MARKER": boom},
                                    send_to=[audit["arn"]])
    role = _create_pipe_role(ctx, source_arn=source["arn"], target_arns=[target["arn"]],
                             function_arns=[enrichment["arn"]])
    _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=role["arn"],
        Enrichment=enrichment["arn"],
        SourceParameters={"SqsQueueParameters": {"BatchSize": 1}},
    )

    sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": boom}))
    sqs.send_message(QueueUrl=source["url"], MessageBody=json.dumps({"marker": ok}))

    # Positive control.
    delivered = _drain_until(ctx, target["url"], lambda got: any(
        isinstance(b, dict) and b.get("marker") == ok for b in got), timeout_s=150,
        description="the healthy record at the target")

    # Barrier: the failing record has been retried at least once after a failure.
    audits = _drain_until(ctx, audit["url"], lambda got: len({
        b["rc"] for b in got if isinstance(b, dict) and b.get("seen") == boom}) >= 2,
        timeout_s=120, description="two distinct enrichment attempts on the failing record")
    boom_rcs = sorted({b["rc"] for b in audits if isinstance(b, dict) and b.get("seen") == boom})
    assert max(boom_rcs) >= 2, f"failing record was not redelivered to the enrichment: {boom_rcs!r}"

    # Effect absent: the target has not received the failing record ...
    delivered += _drain_nowait(ctx, target["url"])
    assert boom not in json.dumps(delivered), (
        f"a record whose enrichment threw reached the target anyway: {delivered!r}"
    )
    # Retention on the source is NOT read off ApproximateNumberOfMessages*: those counters lag and
    # were observed reading 0/0 while the record was in flight. The repair leg below is the proof:
    # the record can only reach the target afterwards, with a receive count >= 2, if the source kept
    # it.

    # Repair the one broken thing: the enrichment stops throwing.
    lam.update_function_configuration(FunctionName=enrichment["name"], Environment={
        "Variables": {"AUDIT_URL": audit["url"], "FAIL_MARKER": "none"}})
    _poll_until(lambda: lam.get_function_configuration(FunctionName=enrichment["name"]),
                lambda c: c.get("LastUpdateStatus") == "Successful", timeout_s=90,
                description="enrichment configuration update applied")
    recovered = _drain_until(ctx, target["url"], lambda got: any(
        isinstance(b, dict) and b.get("marker") == boom for b in got), timeout_s=150,
        description="the retained record at the target after the repair")
    rec = next(b for b in recovered if isinstance(b, dict) and b.get("marker") == boom)
    assert rec.get("enriched") is True and rec.get("rc", 0) >= 2, (
        f"the retained record was not delivered as a retry of the same source message: {rec!r}"
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
