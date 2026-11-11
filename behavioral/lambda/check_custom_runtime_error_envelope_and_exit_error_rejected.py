"""custom-runtime-error-envelope-and-exit-error-rejected."""

from __future__ import annotations

import base64
import io
import json
import re
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "custom-runtime-error-envelope-and-exit-error-rejected"
GROUP = 'rejection'
SERVICES = ['lambda']

TIMEOUT_S = 17

# A shell runtime with three modes selected off a field of the event:
#   err  -> POST .../invocation/<id>/error with an errorType from NO AWS taxonomy, a nonce-bearing
#           message and a two-frame stackTrace, then keep polling.
#   exit -> die mid-invocation with status 7, never answering the Runtime API at all.
#   ok   -> answer normally.
# The `err` document is written by US; the `exit` failure has to be NOTICED, attributed to the
# in-flight request id, and named by Lambda itself.
BOOTSTRAP = r'''#!/bin/sh
set -u
API="$AWS_LAMBDA_RUNTIME_API"
N=0
while true; do
  N=$((N+1))
  curl -sS -LD /tmp/hdr -o /tmp/evt "http://$API/2018-06-01/runtime/invocation/next"
  RID=$(awk 'BEGIN{IGNORECASE=1} /^Lambda-Runtime-Aws-Request-Id:/ {print $2}' /tmp/hdr | tr -d '\r')
  EVENT=$(cat /tmp/evt)
  MODE=$(printf '%s' "$EVENT" | sed -n 's/.*"mode"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
  case "$MODE" in
    err)
      curl -sS -X POST "http://$API/2018-06-01/runtime/invocation/$RID/error" \
        -H "Lambda-Runtime-Function-Error-Type: MyCustom.Boom" \
        -d "{\"errorType\":\"MyCustom.Boom\",\"errorMessage\":\"deliberate $NONCE\",\"stackTrace\":[\"frame-a\",\"frame-b\"]}" >/dev/null
      continue
      ;;
    exit)
      exit 7
      ;;
  esac
  printf '{"invocation":%s,"request_id":"%s","pid":%s,"event":%s}' \
    "$N" "$RID" "$$" "$EVENT" > /tmp/resp.json
  curl -sS -X POST "http://$API/2018-06-01/runtime/invocation/$RID/response" -d @/tmp/resp.json >/dev/null
done
'''


def _make_zip(entries):
    """Build a deployment zip with an explicit unix mode on every member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_ASSUMABLE = "The role defined for the function cannot be assumed by Lambda."
_ROLES = []


def _delete_role(iam, name):
    for call in (
        lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY),
        lambda: iam.delete_role(RoleName=name),
    ):
        try:
            call()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise


def _execution_role(ctx):
    """The execution role this check creates for its functions, one per run."""
    for owner, arn in _ROLES:
        if owner is ctx:
            return arn
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lam-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY)
    _ROLES.append((ctx, arn))
    return arn


def _call_create_function(lam, **kwargs):
    """CreateFunction, retried while IAM propagates the execution role this check created."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") != "InvalidParameterValueException"
                or err.get("Message") != _ROLE_NOT_ASSUMABLE
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        # /aws/lambda/<fn> is created by the service on first invoke and can reappear after
        # this delete.
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_settled(lam, fn, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')!r}")
        if cfg["State"] == "Active":
            return cfg
        time.sleep(1)
    raise AssertionError(f"{fn} did not reach State=Active within {timeout_s}s")


def _invoke(lam, fn, payload):
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode(), LogType="Tail")
    return {
        "status": resp["StatusCode"],
        "function_error": resp.get("FunctionError"),
        "raw": resp["Payload"].read(),
        "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
    }


def _start_request_id(log):
    match = re.search(r"^START RequestId: (\S+)", log, re.M)
    assert match, f"no 'START RequestId:' line in the log tail: {log!r}"
    return match.group(1)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom runtime's posted error document is returned verbatim as an Unhandled error; a runtime
    that exits mid-invocation yields Runtime.ExitError naming the request id; the function recovers.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
    """
    lam = ctx.client("lambda")
    nonce = uuid.uuid4().hex
    fn = ctx.unique_name("sim2real-behav-rterr-")

    _call_create_function(lam, 
        FunctionName=fn, Runtime="provided.al2023", Handler="bootstrap",
        Role=_execution_role(ctx),
        Code={"ZipFile": _make_zip([
            ("bootstrap", BOOTSTRAP.replace("$NONCE", nonce), 0o100755)])},
        Architectures=["x86_64"], MemorySize=512, Timeout=TIMEOUT_S,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_settled(lam, fn)

    # ---- positive control before injecting either failure: the sandbox is healthy -------------
    baseline = _invoke(lam, fn, {"mode": "ok", "nonce": nonce})
    assert baseline["status"] == 200, (
        f"the baseline invoke returned StatusCode {baseline['status']!r} before any failure was "
        f"injected: {baseline['raw']!r}"
    )
    assert baseline["function_error"] is None, (
        f"the baseline invoke reported FunctionError={baseline['function_error']!r} before any "
        f"failure was injected: {baseline['raw']!r}"
    )
    baseline_body = json.loads(baseline["raw"])
    assert baseline_body["invocation"] == 1, (
        f"the baseline invoke's runtime reported invocation={baseline_body['invocation']!r}, "
        f"expected 1 on a freshly created sandbox's first poll"
    )

    # ---- arm 1: the runtime reports its own error document -------------------------------------
    err = _invoke(lam, fn, {"mode": "err"})
    assert err["status"] == 200, (
        f"a function error came back as StatusCode {err['status']!r}; a reported function error is "
        f"still HTTP 200 with X-Amz-Function-Error set. payload {err['raw']!r}"
    )
    assert err["function_error"] == "Unhandled", (
        f"FunctionError was {err['function_error']!r}, expected 'Unhandled' — the "
        f"Lambda-Runtime-Function-Error-Type header on POST .../error was not mapped through"
    )
    body = json.loads(err["raw"])
    assert body["errorType"] == "MyCustom.Boom", (
        f"errorType came back as {body['errorType']!r}, not 'MyCustom.Boom' — an errorType from no "
        f"AWS taxonomy was rewritten instead of passed through, so the body did not come from our "
        f"runtime process"
    )
    assert body["errorMessage"] == f"deliberate {nonce}", (
        f"errorMessage came back as {body['errorMessage']!r}, expected 'deliberate {nonce}' — the "
        f"nonce is generated per run, so no recorded fixture can contain it"
    )
    assert body["stackTrace"] == ["frame-a", "frame-b"], (
        f"stackTrace came back as {body['stackTrace']!r}, expected ['frame-a', 'frame-b'] in order"
    )
    assert set(body) == {"errorType", "errorMessage", "stackTrace"}, (
        f"the error document has keys {sorted(body)!r}; Lambda must return exactly what the "
        f"runtime POSTed, with no injected extras"
    )
    # effect-absent: the reported error REPLACED the response, it did not accompany one
    assert "invocation" not in body, (
        f"the error document also carries the success payload's 'invocation' key: {body!r} — "
        f"POST .../error and POST .../response are not the same endpoint"
    )

    # ---- arm 2: the runtime process dies mid-invocation, answering nothing ---------------------
    died = _invoke(lam, fn, {"mode": "exit"})
    assert died["status"] == 200, (
        f"the killed-runtime invoke returned StatusCode {died['status']!r}, expected 200. payload "
        f"{died['raw']!r}"
    )
    assert died["function_error"] == "Unhandled", (
        f"the killed-runtime invoke reported FunctionError={died['function_error']!r}, expected "
        f"'Unhandled'"
    )
    died_body = json.loads(died["raw"])
    assert died_body["errorType"] == "Runtime.ExitError", (
        f"a runtime that exited mid-invocation produced errorType {died_body['errorType']!r}, "
        f"expected 'Runtime.ExitError' — this string is generated by Lambda's process supervision, "
        f"not by the customer's code"
    )
    assert "exit status 7" in died_body["errorMessage"], (
        f"the message {died_body['errorMessage']!r} does not name the exit status the runtime died "
        f"with, so the platform did not observe the real process outcome"
    )
    in_flight = _start_request_id(died["log"])
    assert in_flight in died_body["errorMessage"], (
        f"the message {died_body['errorMessage']!r} does not name the in-flight request id "
        f"{in_flight!r} — the death was not attributed to the invocation it interrupted"
    )
    assert died_body["errorType"] != body["errorType"], (
        f"a reported error and a runtime death both came back as {body['errorType']!r}; the two "
        f"failure classes must be distinguished, not collapsed into one generic error"
    )

    # ---- positive control on the SAME function: the sandbox recovered from the kill ------------
    ok = _invoke(lam, fn, {"mode": "ok", "nonce": nonce})
    assert ok["status"] == 200, f"the control invoke returned {ok['status']!r}: {ok['raw']!r}"
    assert ok["function_error"] is None, (
        f"the control invoke after two failures reported FunctionError="
        f"{ok['function_error']!r}: {ok['raw']!r} — the function did not recover"
    )
    ok_body = json.loads(ok["raw"])
    assert ok_body["event"] == {"mode": "ok", "nonce": nonce}, (
        f"the control invoke's runtime received event {ok_body['event']!r}"
    )
    assert ok_body["invocation"] == 1, (
        f"the control invoke's runtime reported invocation={ok_body['invocation']!r}; after a "
        f"mid-invocation exit the sandbox must be replaced, so a FRESH poll loop must serve it "
        f"with its counter back at 1 — proving the kill was real and not swallowed"
    )

    # effect-absent: neither failure may park the function itself
    state = lam.get_function_configuration(FunctionName=fn)["State"]
    assert state == "Active", (
        f"after a reported error and a runtime death the function is in State={state!r}, expected "
        f"'Active' — a runtime-process failure must not disable the function"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
