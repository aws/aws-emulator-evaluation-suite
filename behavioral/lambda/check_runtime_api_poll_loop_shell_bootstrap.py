"""runtime-api-poll-loop-shell-bootstrap."""

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


CHECK = "runtime-api-poll-loop-shell-bootstrap"
GROUP = 'compute'
SERVICES = ['lambda']

TIMEOUT_S = 17

# The entire runtime: a shell script implementing the Runtime API by hand (GET invocation/next,
# read the Lambda-Runtime-* response headers, POST <id>/response). It uses only tools present in
# the provided.al2023 image; awk runs with IGNORECASE because header case is not guaranteed.
BOOTSTRAP = r'''#!/bin/sh
set -u
API="$AWS_LAMBDA_RUNTIME_API"
N=0
while true; do
  N=$((N+1))
  curl -sS -LD /tmp/hdr -o /tmp/evt "http://$API/2018-06-01/runtime/invocation/next"
  RID=$(awk 'BEGIN{IGNORECASE=1} /^Lambda-Runtime-Aws-Request-Id:/ {print $2}' /tmp/hdr | tr -d '\r')
  DL=$(awk 'BEGIN{IGNORECASE=1} /^Lambda-Runtime-Deadline-Ms:/ {print $2}' /tmp/hdr | tr -d '\r')
  ARN=$(awk 'BEGIN{IGNORECASE=1} /^Lambda-Runtime-Invoked-Function-Arn:/ {print $2}' /tmp/hdr | tr -d '\r')
  NOW=$(date +%s%3N)
  EVENT=$(cat /tmp/evt)
  HDRS=$(tr -d '\r' < /tmp/hdr | tr '\n' '|')
  MODE=$(printf '%s' "$EVENT" | sed -n 's/.*"mode"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
  if [ "$MODE" = "hang" ]; then
    sleep 600
  fi
  printf '{"invocation":%s,"request_id":"%s","deadline_ms":"%s","arn":"%s","now_ms":"%s","pid":%s,"exec_env":"%s","task_root":"%s","headers":"%s","event":%s}' \
    "$N" "$RID" "$DL" "$ARN" "$NOW" "$$" "${AWS_EXECUTION_ENV:-}" "${LAMBDA_TASK_ROOT:-}" "$HDRS" "$EVENT" > /tmp/resp.json
  curl -sS -X POST "http://$API/2018-06-01/runtime/invocation/$RID/response" -d @/tmp/resp.json >/dev/null
done
'''

_UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")


def _make_zip(entries):
    """Build a deployment zip with an explicit unix mode on every member, as a customer would
    ship an executable bootstrap."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3          # unix, so external_attr is read as a mode
            info.external_attr = mode << 16
            zf.writestr(info, data)
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _exec_role_arn(ctx):
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
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
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function_retrying(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        # Lambda creates /aws/lambda/<fn> on first invoke, so it can reappear after this delete.
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
    before_ms = time.time() * 1000.0
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode(), LogType="Tail")
    after_ms = time.time() * 1000.0
    raw = resp["Payload"].read()
    return {
        "status": resp["StatusCode"],
        "function_error": resp.get("FunctionError"),
        "raw": raw,
        "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
        "before_ms": before_ms,
        "after_ms": after_ms,
    }


def _body(fn, r):
    assert r["status"] == 200, f"{fn}: StatusCode {r['status']!r}, payload {r['raw']!r}"
    assert r["function_error"] is None, (
        f"{fn}: FunctionError={r['function_error']!r}, payload {r['raw']!r}"
    )
    return json.loads(r["raw"])


def _start_request_id(log):
    match = re.search(r"^START RequestId: (\S+)", log, re.M)
    assert match, f"no 'START RequestId:' line in the log tail: {log!r}"
    return match.group(1)


def _report_line(log):
    match = re.search(r"^REPORT RequestId: .*$", log, re.M)
    assert match, f"no 'REPORT RequestId:' line in the log tail: {log!r}"
    return match.group(0)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A hand-written shell runtime serves three invokes from one process via the Runtime API,
    with correct request ids, ARN and deadline headers, and a deadline overrun kills the sandbox.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html
    """
    lam = ctx.client("lambda")
    nonce = uuid.uuid4().hex
    fn = ctx.unique_name("sim2real-behav-rtapi-")

    created = _create_function_retrying(
        lam,
        FunctionName=fn, Runtime="provided.al2023", Handler="bootstrap",
        Role=_exec_role_arn(ctx),
        Code={"ZipFile": _make_zip([("bootstrap", BOOTSTRAP, 0o100755)])},
        Architectures=["x86_64"], MemorySize=512, Timeout=TIMEOUT_S,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-rtapi"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    arn = created["FunctionArn"]
    _wait_settled(lam, fn)

    results, bodies = [], []
    for n in (1, 2, 3):
        r = _invoke(lam, fn, {"n": n, "nonce": nonce, "mode": "ok"})
        results.append(r)
        bodies.append(_body(fn, r))

    b1, b2, b3 = bodies

    # (1) the id the Runtime API served the script is a real v4 uuid
    assert _UUID4.fullmatch(b1["request_id"]), (
        f"the runtime read request id {b1['request_id']!r} off the Lambda-Runtime-Aws-Request-Id "
        f"header; it is not a lowercase RFC-4122 v4 uuid"
    )
    # (2) ... and it is the SAME id Lambda reports to the caller's own log tail
    for idx, (r, body) in enumerate(zip(results, bodies), start=1):
        logged = _start_request_id(r["log"])
        assert body["request_id"] == logged, (
            f"invoke {idx}: the runtime was served request id {body['request_id']!r} but Lambda's "
            f"own START line reports {logged!r} — the runtime API and the platform disagree about "
            f"which invocation this is"
        )
    # (3) three invokes are three distinct ids
    ids = [b["request_id"] for b in bodies]
    assert len(set(ids)) == 3, f"three invokes were served request ids {ids!r}, expected 3 distinct"

    # (4) the event body reaches the custom runtime byte-for-byte, uncrossed
    for n, body in enumerate(bodies, start=1):
        assert body["event"] == {"n": n, "nonce": nonce, "mode": "ok"}, (
            f"invoke {n}: the runtime received event {body['event']!r}, not the payload that was "
            f"sent — GET /invocation/next delivered the wrong or a mangled body"
        )

    # (5) ONE process served all three, from its own poll loop
    counters = [b["invocation"] for b in bodies]
    assert counters == [1, 2, 3], (
        f"the runtime's own in-process counter reported {counters!r} across three sequential "
        f"invokes, expected [1, 2, 3] — the execution environment was not reused, so the poll "
        f"loop was restarted rather than parked on GET /invocation/next"
    )
    pids = {b["pid"] for b in bodies}
    assert len(pids) == 1, (
        f"the runtime reported pids {sorted(pids)!r} across three invokes; one poll loop means one "
        f"process"
    )

    # (6) the invoked-function ARN header is the real, fully qualified ARN
    for n, body in enumerate(bodies, start=1):
        assert body["arn"] == arn, (
            f"invoke {n}: Lambda-Runtime-Invoked-Function-Arn was {body['arn']!r}, but "
            f"CreateFunction returned {arn!r}"
        )

    # (7) the deadline agrees with the configured Timeout AND with the runtime's own wall clock
    for n, body in enumerate(bodies, start=1):
        delta = int(body["deadline_ms"]) - int(body["now_ms"])
        assert TIMEOUT_S * 1000 - 3000 <= delta <= TIMEOUT_S * 1000, (
            f"invoke {n}: Lambda-Runtime-Deadline-Ms minus the runtime's own clock is {delta}ms, "
            f"outside [{TIMEOUT_S * 1000 - 3000}, {TIMEOUT_S * 1000}] for Timeout={TIMEOUT_S}s — "
            f"the deadline is not derived from this function's configured timeout"
        )
    # (8) ... and with the CALLER's clock, so a hardcoded constant cannot pass
    for n, (r, body) in enumerate(zip(results, bodies), start=1):
        deadline = int(body["deadline_ms"])
        lo, hi = r["before_ms"], r["after_ms"] + TIMEOUT_S * 1000
        assert lo <= deadline <= hi, (
            f"invoke {n}: deadline {deadline} is outside the caller's own window "
            f"[{lo:.0f}, {hi:.0f}] — it was not computed from the time of this invocation"
        )
    # (9) the deadline is recomputed per invoke, not once per container
    assert int(b3["deadline_ms"]) > int(b1["deadline_ms"]), (
        f"invoke 3's deadline {b3['deadline_ms']!r} is not later than invoke 1's "
        f"{b1['deadline_ms']!r} — the deadline is per-container, not per-invocation"
    )

    # (10) the process environment the sandbox exec'd the runtime with
    for n, body in enumerate(bodies, start=1):
        assert body["exec_env"] == "AWS_Lambda_provided.al2023", (
            f"invoke {n}: the runtime process saw AWS_EXECUTION_ENV={body['exec_env']!r}"
        )
        assert body["task_root"] == "/var/task", (
            f"invoke {n}: the runtime process saw LAMBDA_TASK_ROOT={body['task_root']!r}"
        )

    # (11) the documented headers were actually served on GET /invocation/next
    for n, body in enumerate(bodies, start=1):
        served = body["headers"].lower()
        for header in ("lambda-runtime-aws-request-id", "lambda-runtime-deadline-ms",
                       "lambda-runtime-invoked-function-arn"):
            assert header in served, (
                f"invoke {n}: {header!r} was absent from the response headers of "
                f"GET /invocation/next; the runtime saw {body['headers']!r}"
            )

    # Injected failure: the runtime overruns the deadline it was handed.
    hung = _invoke(lam, fn, {"n": 4, "nonce": nonce, "mode": "hang"})
    assert hung["status"] == 200, f"the timed-out invoke returned StatusCode {hung['status']!r}"
    assert hung["function_error"] == "Unhandled", (
        f"the timed-out invoke reported FunctionError={hung['function_error']!r}, expected "
        f"'Unhandled' — Lambda did not enforce the deadline it advertised to the runtime"
    )
    hung_body = json.loads(hung["raw"])
    assert hung_body["errorType"] == "Sandbox.Timedout", (
        f"a runtime that overran its deadline produced errorType {hung_body['errorType']!r}, "
        f"expected 'Sandbox.Timedout'"
    )
    assert f"Task timed out after {TIMEOUT_S}.00 seconds" in hung_body["errorMessage"], (
        f"the timeout message {hung_body['errorMessage']!r} does not name the configured "
        f"{TIMEOUT_S}s timeout — the watchdog fired on some other budget"
    )
    assert "Status: timeout" in _report_line(hung["log"]), (
        f"Lambda's own REPORT line does not record the timeout: {_report_line(hung['log'])!r}"
    )

    # ... and the kill was real: the next invoke is served by a FRESH poll loop, whose counter
    # restarted at 1. (The sandbox pid is always 2, so the counter is the only witness.)
    after = _body(fn, _invoke(lam, fn, {"n": 5, "nonce": nonce, "mode": "ok"}))
    assert after["invocation"] == 1, (
        f"after the timeout the runtime reported invocation={after['invocation']!r}; a killed "
        f"sandbox must be replaced, so a fresh poll loop must start its counter at 1"
    )
    assert after["request_id"] not in set(ids), (
        f"the post-timeout invoke was served an already-used request id {after['request_id']!r}"
    )

    # effect-absent: a runtime crash and a timeout must not park the function itself
    state = lam.get_function_configuration(FunctionName=fn)["State"]
    assert state == "Active", (
        f"after a deadline overrun the function is in State={state!r}, expected 'Active' — a "
        f"runtime-process failure must not disable the function"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
