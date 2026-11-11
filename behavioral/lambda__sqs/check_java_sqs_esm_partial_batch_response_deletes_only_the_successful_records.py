"""java-sqs-esm-partial-batch-response-deletes-only-the-successful-records."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-sqs-esm-partial-batch-response-deletes-only-the-successful-records"
GROUP = "event-source-mapping"
SERVICES = ["lambda", "sqs"]

# com.amazonaws.services.lambda.runtime.RequestHandler<Map<String,Object>, Map<String,Object>>,
# no SQSEvent/SQSBatchResponse POJOs: every SQS record field is read through the generic Map the
# runtime hands a Map-typed RequestHandler. The handler logs each record's messageId, body,
# ApproximateReceiveCount and eventSourceARN, then names the "poison" record's messageId in
# batchItemFailures so only it is redelivered. Compiled once under JDK 8 (class file major
# version 52).
_SHA256 = "087bebd2c6b784272f48511abb631f46bb349efc188c444874ade824ee7904e2"

_B64 = (  # @@GENERATED@@ probe/SqsBatchHandler.class
    "yv66vgAAADQAfQoAJgA8BwA9CgACADwIAD4LAAoAPwcAQAsABgBBCwBCAEMLAEIARAcARQgARgcARwgASAgASQgASggASwkA"
    "TABNBwBOCgASADwIAE8KABIAUAgAUQgAUgoAEgBTCABUCgASAFUKAFYAVwgAWAoADABZBwBaCgAeADwIAFsLAAoAXAsABgBd"
    "CABeCgAlAF8HAGAHAGEHAGIBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQANaGFuZGxlUmVxdWVz"
    "dAEATyhMamF2YS91dGlsL01hcDtMY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0OylMamF2"
    "YS91dGlsL01hcDsBAA1TdGFja01hcFRhYmxlBwBABwBjBwBgBwBFBwBkBwBHBwBhAQAJU2lnbmF0dXJlAQCbKExqYXZhL3V0"
    "aWwvTWFwPExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0Oz47TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFt"
    "YmRhL3J1bnRpbWUvQ29udGV4dDspTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7"
    "PjsBAFUoTGphdmEvbGFuZy9PYmplY3Q7TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDsp"
    "TGphdmEvbGFuZy9PYmplY3Q7AQC0TGphdmEvbGFuZy9PYmplY3Q7TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1"
    "bnRpbWUvUmVxdWVzdEhhbmRsZXI8TGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7"
    "PjtMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+Oz47AQAKU291cmNlRmlsZQEA"
    "FFNxc0JhdGNoSGFuZGxlci5qYXZhDAAoACkBABNqYXZhL3V0aWwvQXJyYXlMaXN0AQAHUmVjb3JkcwwAZQBmAQAOamF2YS91"
    "dGlsL0xpc3QMAGcAaAcAYwwAaQBqDABrAGwBAA1qYXZhL3V0aWwvTWFwAQAJbWVzc2FnZUlkAQAQamF2YS9sYW5nL1N0cmlu"
    "ZwEABGJvZHkBAAphdHRyaWJ1dGVzAQAXQXBwcm94aW1hdGVSZWNlaXZlQ291bnQBAA5ldmVudFNvdXJjZUFSTgcAbQwAbgBv"
    "AQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIBAApTUVNSRUMgaWQ9DABwAHEBAAYgYm9keT0BAA4gcmVjZWl2ZUNvdW50PQwA"
    "cAByAQAQIGV2ZW50U291cmNlQVJOPQwAcwB0BwB1DAB2AHcBAAZwb2lzb24MAHgAeQEAEWphdmEvdXRpbC9IYXNoTWFwAQAO"
    "aXRlbUlkZW50aWZpZXIMAHoAewwAfAB5AQARYmF0Y2hJdGVtRmFpbHVyZXMMACwALQEAFXByb2JlL1Nxc0JhdGNoSGFuZGxl"
    "cgEAEGphdmEvbGFuZy9PYmplY3QBADRjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL1JlcXVlc3RIYW5k"
    "bGVyAQASamF2YS91dGlsL0l0ZXJhdG9yAQAtY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0"
    "AQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAhpdGVyYXRvcgEAFigpTGphdmEvdXRp"
    "bC9JdGVyYXRvcjsBAAdoYXNOZXh0AQADKClaAQAEbmV4dAEAFCgpTGphdmEvbGFuZy9PYmplY3Q7AQAQamF2YS9sYW5nL1N5"
    "c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEv"
    "bGFuZy9TdHJpbmdCdWlsZGVyOwEALShMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEACHRv"
    "U3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9s"
    "YW5nL1N0cmluZzspVgEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgEAA3B1dAEAOChMamF2YS9sYW5nL09iamVj"
    "dDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQADYWRkACEAJQAmAAEAJwAAAAMAAQAoACkAAQAqAAAA"
    "HQABAAEAAAAFKrcAAbEAAAABACsAAAAGAAEAAAAJAAEALAAtAAIAKgAAAagAAwANAAAA97sAAlm3AANOKxIEuQAFAgDAAAY6"
    "BBkEuQAHAQA6BRkFuQAIAQCZALsZBbkACQEAwAAKOgYZBhILuQAFAgDAAAw6BxkGEg25AAUCAMAADDoIGQYSDrkABQIAwAAK"
    "OgkZCccABwGnAAwZCRIPuQAFAgA6ChkGEhC5AAUCADoLsgARuwASWbcAExIUtgAVGQe2ABUSFrYAFRkItgAVEhe2ABUZCrYA"
    "GBIZtgAVGQu2ABi2ABq2ABsSHBkItgAdmQAhuwAeWbcAHzoMGQwSIBkHuQAhAwBXLRkMuQAiAgBXp/9BuwAeWbcAHzoFGQUS"
    "Iy25ACEDAFcZBbAAAAACACsAAABGABEAAAAMAAgADQAVAA4ANAAPAEIAEABQABEAXgASAHIAEwB9ABQAtQAWAL8AFwDIABgA"
    "1AAZAN0AGwDgABwA6QAdAPQAHgAuAAAAUwAF/gAeBwAvBwAvBwAw/wBIAAoHADEHADIHADMHAC8HAC8HADAHADIHADQHADQH"
    "ADIAAEgHADX/AGwABgcAMQcAMgcAMwcALwcALwcAMAAA+gACADYAAAACADcQQQAsADgAAQAqAAAAIgADAAMAAAAKKivAAAos"
    "tgAksAAAAAEAKwAAAAYAAQAAAAkAAgA2AAAAAgA5ADoAAAACADs="
)

_OK_BODIES = ["ok-0", "ok-1", "ok-2", "ok-3"]
_POISON = "poison"
_MAX_RECEIVE = 2
_VISIBILITY_S = 30


def _deployment_zip() -> bytes:
    raw = base64.b64decode(_B64)
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256, f"embedded class is sha256 {got!r}, pinned {_SHA256!r}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("probe/SqsBatchHandler.class", raw)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _reap_log_group(ctx, logs, name: str, *, reads: int = 3, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"reaping log group {name}: the run budget ended first; not graded")
                raise AssertionError(f"log group {name} still present after its reap budget")
            time.sleep(interval_s)


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _create_queue(ctx, sqs, label, *, redrive_to=None):
    name = ctx.unique_name(f"sim2real-behav-javasqs-{label}")
    attrs = {"VisibilityTimeout": str(_VISIBILITY_S)}
    if redrive_to:
        attrs["RedrivePolicy"] = json.dumps(
            {"deadLetterTargetArn": redrive_to, "maxReceiveCount": _MAX_RECEIVE})
    created = sqs.create_queue(QueueName=name, Attributes=attrs, tags={"sim2real": CHECK})
    url = created["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _execution_role(ctx, *, consume_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-javasqs-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    logs_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=logs_policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=logs_policy),
                             "NoSuchEntity"))
    inline = "sqs-consume"
    iam.put_role_policy(RoleName=name, PolicyName=inline, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes",
                       "sqs:ChangeMessageVisibility"],
            "Resource": consume_arn}]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName=inline),
                             "NoSuchEntity"))
    return arn


def _create(ctx, lam, kwargs, cap_s=120):
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "cannot be assumed by Lambda" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                if propagating and _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateFunction role propagation: the run budget ended first; not graded"
                    ) from exc
                raise
            time.sleep(3.0)


def _wait_active(ctx, lam, fn, cap_s=300):
    return _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=fn),
        lambda cfg: cfg["State"] == "Active", timeout_s=_budget_s(ctx, cap_s), interval_s=2.0,
        description=f"{fn} reaching State=Active")


def _function(ctx, lam, logs, **kwargs) -> str:
    fn = kwargs["FunctionName"]
    _create(ctx, lam, kwargs)
    ctx.on_cleanup(lambda: _reap_log_group(ctx, logs, f"/aws/lambda/{fn}"))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_active(ctx, lam, fn)
    return fn


def _create_esm(ctx, lam, fn, source_arn):
    created = lam.create_event_source_mapping(
        FunctionName=fn, EventSourceArn=source_arn, BatchSize=5, Enabled=True,
        MaximumBatchingWindowInSeconds=0, FunctionResponseTypes=["ReportBatchItemFailures"])
    uuid = created["UUID"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_event_source_mapping(UUID=uuid),
                             "ResourceNotFoundException"))
    return uuid


def _wait_esm_enabled(ctx, lam, uuid, cap_s=180.0):
    return _poll_until(
        ctx,
        lambda: lam.get_event_source_mapping(UUID=uuid),
        lambda esm: esm.get("State") == "Enabled", timeout_s=_budget_s(ctx, cap_s), interval_s=5.0,
        description=f"event source mapping {uuid} reaching State=Enabled")


def _log_lines(logs, group, prefix, *, since_ms):
    out = []
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, startTime=since_ms, filterPattern=f'"{prefix}"')
        for page in pages:
            for ev in page["events"]:
                if prefix in ev["message"]:
                    out.append(ev["message"].strip())
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    return out


def _parse_sqsrec(line: str) -> dict:
    """'SQSREC id=<x> body=<y> receiveCount=<z> eventSourceARN=<w>' -> a dict of the four fields."""
    body = line.split("SQSREC ", 1)[1]
    parts = {}
    for key in ("id", "body", "receiveCount", "eventSourceARN"):
        marker = f"{key}="
        start = body.index(marker) + len(marker)
        rest = body[start:]
        end = len(rest)
        for other in ("id=", "body=", "receiveCount=", "eventSourceARN="):
            if other == marker:
                continue
            idx = rest.find(f" {other}")
            if idx != -1 and idx < end:
                end = idx
        parts[key] = rest[:end].strip()
    return parts


# timing:real-time — visibility: 30 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Java RequestHandler<Map,Map> reads SQS record fields (messageId, body, attributes,
    eventSourceARN) through the generic Map the runtime hands it, and its returned
    batchItemFailures deletes every unnamed record while the named one is redelivered.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")

    dlq_url, dlq_arn = _create_queue(ctx, sqs, "dlq-")
    src_url, src_arn = _create_queue(ctx, sqs, "src-", redrive_to=dlq_arn)
    role_arn = _execution_role(ctx, consume_arn=src_arn)
    zip_bytes = _deployment_zip()

    fn = ctx.unique_name("sim2real-behav-javasqs-fn-")
    fn = _function(ctx, lam, logs, FunctionName=fn, Runtime="java8.al2",
                   Handler="probe.SqsBatchHandler", Role=role_arn,
                   Code={"ZipFile": zip_bytes}, MemorySize=512, Timeout=20,
                   Tags={"sim2real": CHECK})

    esm = _create_esm(ctx, lam, fn, src_arn)
    _wait_esm_enabled(ctx, lam, esm)

    since_ms = int(time.time() * 1000) - 2000
    for body in [*_OK_BODIES, _POISON]:
        sqs.send_message(QueueUrl=src_url, MessageBody=body)

    group = f"/aws/lambda/{fn}"

    def _seen():
        return [_parse_sqsrec(ln) for ln in _log_lines(logs, group, "SQSREC", since_ms=since_ms)]

    def _dlq_has_poison():
        got = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = got.get("Messages", [])
        for m in msgs:
            sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=m["ReceiptHandle"])
        return [m["Body"] for m in msgs]

    dead = []

    def _probe():
        nonlocal dead
        dead.extend(_dlq_has_poison())
        return dead

    _poll_until(ctx, _probe, lambda d: len(d) > 0, timeout_s=_budget_s(ctx, 420.0), interval_s=5.0,
                description="the poison record reaching its redrive target")
    assert dead == [_POISON], (
        f"the redrive target must receive exactly the poison body, got {dead!r}")

    def _by_body():
        by_body: dict[str, list[dict]] = {}
        for r in _seen():
            by_body.setdefault(r["body"], []).append(r)
        return by_body

    by_body = _poll_until(
        ctx, _by_body,
        lambda d: all(len(d.get(b, [])) >= 1 for b in _OK_BODIES) and len(d.get(_POISON, [])) >= 2,
        timeout_s=_budget_s(ctx, 120.0), interval_s=2.0,
        description="every OK body and both poison deliveries reaching the Lambda logs")

    for body in _OK_BODIES:
        seen = by_body.get(body, [])
        assert len(seen) == 1, (
            f"{body!r} was not named in batchItemFailures, so the Java handler must see it "
            f"exactly once; it logged {len(seen)} time(s): {seen!r}")
        assert seen[0]["receiveCount"] == "1", (
            f"{body!r}'s ApproximateReceiveCount must be 1 on its only delivery, "
            f"handler logged {seen[0]['receiveCount']!r}")
        assert seen[0]["eventSourceARN"] == src_arn, (
            f"eventSourceARN reaching the handler was {seen[0]['eventSourceARN']!r}, "
            f"expected the source queue's own ARN {src_arn!r}")

    poison_seen = by_body.get(_POISON, [])
    assert 2 <= len(poison_seen) <= _MAX_RECEIVE, (
        f"the poison record is named in batchItemFailures every time, so SQS must redeliver it "
        f"at least twice and at most maxReceiveCount={_MAX_RECEIVE} times before the redrive "
        f"fires; the Java handler logged it {len(poison_seen)} time(s): {poison_seen!r}")

    final = sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
    assert not final.get("Messages"), (
        f"the source queue must be empty once the poison record redrove, still holds "
        f"{final.get('Messages')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
