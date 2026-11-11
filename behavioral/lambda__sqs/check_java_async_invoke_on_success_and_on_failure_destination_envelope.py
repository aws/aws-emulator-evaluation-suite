"""java-async-invoke-on-success-and-on-failure-destination-envelope."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-async-invoke-on-success-and-on-failure-destination-envelope"
GROUP = "data-plane"
SERVICES = ["lambda", "sqs"]

# com.amazonaws.services.lambda.runtime.RequestHandler<Map<String,Object>, Map<String,Object>>:
# the handler returns a richly-typed Map (nested list included) on success, which the Lambda
# Java runtime serializes into the OnSuccess destination's responsePayload, and it throws a
# RuntimeException on the "fail" input, which the platform reports to OnFailure as
# errorType=java.lang.RuntimeException with the exception's own message -- a Java-specific error
# shape no Python/Node handler produces. Compiled once under JDK 8 (class file major version 52).
_SHA256 = "96e4a4486c2940300ae5da28caa826f2391ec7fc826c4cb6b53159c885ad379b"

_B64 = (  # @@GENERATED@@ probe/AsyncDestHandler.class
    "yv66vgAAADQAZgoAIAAwCAAxCwAdADIHADMKAAQANAcANQcANgoABwAwCAA3CgAHADgIADkKAAcAOgoABwA7CgAGADwIAD0H"
    "AD4HAD8KABEAMAgAQAoAEABBCgBCAEMLAB0ARAgARQkABABGBwBHCgAZADALAEgASQgASgcASwoAHwBMBwBNBwBOBwBPAQAG"
    "PGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEADWhhbmRsZVJlcXVlc3QBAE8oTGphdmEvdXRpbC9NYXA7"
    "TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspTGphdmEvdXRpbC9NYXA7AQANU3RhY2tN"
    "YXBUYWJsZQcAMwEACVNpZ25hdHVyZQEAmyhMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09i"
    "amVjdDs+O0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL3V0aWwvTWFwPExq"
    "YXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0Oz47AQBVKExqYXZhL2xhbmcvT2JqZWN0O0xjb20vYW1hem9uYXdz"
    "L3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL2xhbmcvT2JqZWN0OwEAtExqYXZhL2xhbmcvT2JqZWN0"
    "O0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50aW1lL1JlcXVlc3RIYW5kbGVyPExqYXZhL3V0aWwvTWFwPExq"
    "YXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0Oz47TGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGph"
    "dmEvbGFuZy9PYmplY3Q7Pjs+OwEAClNvdXJjZUZpbGUBABVBc3luY0Rlc3RIYW5kbGVyLmphdmEMACIAIwEABGZhaWwMAFAA"
    "UQEAEWphdmEvbGFuZy9Cb29sZWFuDABSAFMBABpqYXZhL2xhbmcvUnVudGltZUV4Y2VwdGlvbgEAF2phdmEvbGFuZy9TdHJp"
    "bmdCdWlsZGVyAQAFYm9vbS0MAFQAVQEABm1hcmtlcgwAVABWDABXAFgMACIAWQEAAW4BABBqYXZhL2xhbmcvTnVtYmVyAQAR"
    "amF2YS91dGlsL0hhc2hNYXABAAdkb3VibGVkDABaAFsHAFwMAF0AXgwAXwBgAQAEZmxhZwwAYQBiAQATamF2YS91dGlsL0Fy"
    "cmF5TGlzdAcAYwwAZABlAQAEbGlzdAEADWphdmEvdXRpbC9NYXAMACYAJwEAFnByb2JlL0FzeW5jRGVzdEhhbmRsZXIBABBq"
    "YXZhL2xhbmcvT2JqZWN0AQA0Y29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9SZXF1ZXN0SGFuZGxlcgEA"
    "A2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAMYm9vbGVhblZhbHVlAQADKClaAQAGYXBw"
    "ZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAtKExqYXZhL2xhbmcvT2JqZWN0"
    "OylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEAFShMamF2YS9s"
    "YW5nL1N0cmluZzspVgEACGludFZhbHVlAQADKClJAQARamF2YS9sYW5nL0ludGVnZXIBAAd2YWx1ZU9mAQAWKEkpTGphdmEv"
    "bGFuZy9JbnRlZ2VyOwEAA3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9P"
    "YmplY3Q7AQAEVFJVRQEAE0xqYXZhL2xhbmcvQm9vbGVhbjsBAA5qYXZhL3V0aWwvTGlzdAEAA2FkZAEAFShMamF2YS9sYW5n"
    "L09iamVjdDspWgAhAB8AIAABACEAAAADAAEAIgAjAAEAJAAAAB0AAQABAAAABSq3AAGxAAAAAQAlAAAABgABAAAACQABACYA"
    "JwACACQAAAEYAAUABwAAAL4rEgK5AAMCAMAABE4txgAsLbYABZkAJbsABlm7AAdZtwAIEgm2AAorEgu5AAMCALYADLYADbcA"
    "Dr8rEg+5AAMCAMAAEDoEuwARWbcAEjoFGQUSExkEtgAUBWi4ABW5ABYDAFcZBRILKxILuQADAgC5ABYDAFcZBRIXsgAYuQAW"
    "AwBXuwAZWbcAGjoGGQYEuAAVuQAbAgBXGQYFuAAVuQAbAgBXGQYGuAAVuQAbAgBXGQUSHBkGuQAWAwBXGQWwAAAAAgAlAAAA"
    "OgAOAAAACwAMAAwAFwANADkADwBGABAATwARAGMAEgB1ABMAggAUAIsAFQCXABYAowAXAK8AGAC7ABkAKAAAAAgAAfwAOQcA"
    "KQAqAAAAAgArEEEAJgAsAAEAJAAAACIAAwADAAAACiorwAAdLLYAHrAAAAABACUAAAAGAAEAAAAJAAIAKgAAAAIALQAuAAAA"
    "AgAv"
)

_DELIVERY_TIMEOUT_S = 150


def _deployment_zip() -> bytes:
    raw = base64.b64decode(_B64)
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256, f"embedded class is sha256 {got!r}, pinned {_SHA256!r}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("probe/AsyncDestHandler.class", raw)
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


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
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
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _create_queue(ctx, sqs, label):
    name = ctx.unique_name(f"sim2real-behav-javadest-{label}")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _execution_role(ctx, *, send_to):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-javadest-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy),
                             "NoSuchEntity"))
    inline = "sqs-destinations"
    iam.put_role_policy(RoleName=name, PolicyName=inline, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": send_to}]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName=inline),
                             "NoSuchEntity"))
    return arn


def _create(ctx, lam, kwargs, timeout_s=120):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
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
                        "role propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(2.0)


def _wait_active(ctx, lam, fn, timeout_s=300):
    return _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=fn),
        lambda cfg: cfg["State"] == "Active", timeout_s=timeout_s, interval_s=2.0,
        description=f"{fn} reaching State=Active")


def _function(ctx, lam, logs, **kwargs):
    fn = kwargs["FunctionName"]
    _create(ctx, lam, kwargs)
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_active(ctx, lam, fn)
    return fn


def _put_eic(ctx, lam, fn, *, on_success_arn, on_failure_arn, timeout_s=90.0):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while True:
        try:
            lam.put_function_event_invoke_config(
                FunctionName=fn, MaximumRetryAttempts=0,
                DestinationConfig={"OnSuccess": {"Destination": on_success_arn},
                                   "OnFailure": {"Destination": on_failure_arn}})
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "does not have permissions" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                if propagating and _budget_spent(ctx):
                    raise TimeoutError(
                        "role propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(2.0)


def _invoke_event(lam, fn, payload):
    resp = lam.invoke(FunctionName=fn, InvocationType="Event",
                      Payload=json.dumps(payload).encode())
    assert resp["StatusCode"] == 202, f"async invoke of {fn} returned {resp['StatusCode']!r}"
    return resp["ResponseMetadata"]["RequestId"]


def _await_message(ctx, sqs, url, *, timeout_s):
    def _probe():
        got = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        return got.get("Messages", [])

    msgs = _poll_until(ctx, _probe, lambda m: len(m) > 0, timeout_s=timeout_s, interval_s=2.0,
                       description=f"a message arriving on {url}")
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])
    return json.loads(msgs[0]["Body"])


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Java RequestHandler's return value serializes verbatim into the OnSuccess destination's
    responsePayload; its thrown RuntimeException reports to OnFailure as errorType
    java.lang.RuntimeException with the exception's own message, after MaximumRetryAttempts=0.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-exceptions.html
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")

    ok_url, ok_arn = _create_queue(ctx, sqs, "ok-")
    fail_url, fail_arn = _create_queue(ctx, sqs, "fail-")
    role_arn = _execution_role(ctx, send_to=[ok_arn, fail_arn])

    fn = ctx.unique_name("sim2real-behav-javadest-fn-")
    fn = _function(ctx, lam, logs, FunctionName=fn, Runtime="java17.al2023",
                   Handler="probe.AsyncDestHandler", Role=role_arn,
                   Code={"ZipFile": _deployment_zip()}, MemorySize=512, Timeout=20,
                   Tags={"sim2real": CHECK})
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]
    _put_eic(ctx, lam, fn, on_success_arn=ok_arn, on_failure_arn=fail_arn)

    ok_marker = ctx.unique_name("ok-")
    ok_request_id = _invoke_event(lam, fn, {"marker": ok_marker, "n": 7, "fail": False})

    ok_record = _await_message(ctx, sqs, ok_url, timeout_s=_DELIVERY_TIMEOUT_S)
    assert ok_record.get("version") == "1.0", f"record version: {ok_record.get('version')!r}"
    ok_rc = ok_record.get("requestContext", {})
    assert ok_rc.get("condition") == "Success", f"requestContext: {ok_rc!r}"
    assert ok_rc.get("requestId") == ok_request_id, "the record names another request id"
    assert ok_rc.get("functionArn") == f"{fn_arn}:$LATEST", (
        f"functionArn is {ok_rc.get('functionArn')!r}, expected {fn_arn}:$LATEST")
    assert ok_record.get("requestPayload") == {"marker": ok_marker, "n": 7, "fail": False}, (
        f"requestPayload: {ok_record.get('requestPayload')!r}")
    assert ok_record.get("responsePayload") == {
        "doubled": 14, "marker": ok_marker, "flag": True, "list": [1, 2, 3]}, (
        f"the Java handler's returned Map must serialize verbatim into responsePayload; got "
        f"{ok_record.get('responsePayload')!r}")

    fail_marker = ctx.unique_name("fail-")
    fail_request_id = _invoke_event(lam, fn, {"marker": fail_marker, "fail": True})

    fail_record = _await_message(ctx, sqs, fail_url, timeout_s=_DELIVERY_TIMEOUT_S)
    fail_rc = fail_record.get("requestContext", {})
    assert fail_rc.get("condition") == "RetriesExhausted", f"requestContext: {fail_rc!r}"
    assert fail_rc.get("approximateInvokeCount") == 1, (
        f"MaximumRetryAttempts=0 must yield approximateInvokeCount 1, got "
        f"{fail_rc.get('approximateInvokeCount')!r}")
    assert fail_rc.get("requestId") == fail_request_id, "the record names another request id"
    assert fail_record.get("requestPayload") == {"marker": fail_marker, "fail": True}, (
        f"requestPayload: {fail_record.get('requestPayload')!r}")
    resp = fail_record.get("responsePayload") or {}
    assert resp.get("errorType") == "java.lang.RuntimeException", (
        f"a thrown RuntimeException must report errorType java.lang.RuntimeException, got "
        f"{resp.get('errorType')!r}")
    assert resp.get("errorMessage") == f"boom-{fail_marker}", (
        f"errorMessage was {resp.get('errorMessage')!r}, expected the exception's own message "
        f"'boom-{fail_marker}'")
    assert resp.get("stackTrace"), (
        f"a Java exception's destination record must carry a non-empty stackTrace, got "
        f"{resp.get('stackTrace')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
