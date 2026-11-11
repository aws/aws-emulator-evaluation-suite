"""stream-handler-throw-delivers-no-bytes-and-no-error-code."""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-handler-throw-delivers-no-bytes-and-no-error-code"
GROUP = 'invoke_stream'
SERVICES = ['lambda']

SEGMENTS = ["one|", "two-2|", "three-33|"]
BODY = "".join(SEGMENTS).encode()
GAP_MS = 600
THROW_MESSAGE = "sim2real-deliberate-streaming-failure"

# One function, three modes. The negative differs from the positive control in exactly one input
# field, so nothing but the handler's own outcome changes between the legs.
STREAM_JS = """
const { setTimeout: sleep } = require('timers/promises');

const SEGMENTS = %s;
const GAP_MS = %d;

exports.handler = awslambda.streamifyResponse(async (event, responseStream, _context) => {
  const mode = event.mode;
  console.log(`MODE ${mode}`);
  if (mode === 'throw') {
    throw new Error(%s);
  }
  if (mode === 'silent') {
    responseStream.end();
    return;
  }
  for (let i = 0; i < SEGMENTS.length; i++) {
    responseStream.write(SEGMENTS[i]);
    if (i < SEGMENTS.length - 1) {
      await sleep(GAP_MS);
    }
  }
  responseStream.end();
});
""" % (json.dumps(SEGMENTS), GAP_MS, json.dumps(THROW_MESSAGE))

# The same throw without streamifyResponse: proves an unhandled error IS surfaced off the
# streaming path, so the silence is a property of streaming.
BUFFERED_JS = """
exports.handler = async (_event) => {
  console.log('MODE buffered-throw');
  throw new Error(%s);
};
""" % json.dumps(THROW_MESSAGE)


@tags("axis:negative-delivery", "cap:c3", "cap:c6", "concern:data-plane",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A streaming handler that throws before writing gets 200, no PayloadChunk and no ErrorCode,
    exactly like an empty stream; only its log tail records the error, while a non-streaming
    handler throwing the same error returns FunctionError='Unhandled'.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-response-streaming.html
    """
    lam = ctx.client("lambda")
    role_arn = _execution_role(ctx)

    fn = ctx.unique_name("sim2real-behav-strmthrow-")
    _create_function(
        ctx, lam,
        FunctionName=fn,
        Runtime="nodejs22.x",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.js": STREAM_JS})},
        MemorySize=512,
        Timeout=60,
        Tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    _wait_active(lam, fn)

    # ---- (1) the bytes arrive; legs differ from each other in one input only ----
    ok_frames, ok_complete = _stream(lam, fn, "write")
    assert len(ok_frames) >= 2, (
        f"the positive control delivered {len(ok_frames)} frame(s), so this target does not stream "
        f"at all and the absence asserted below would prove nothing: {ok_frames!r}"
    )
    assert b"".join(ok_frames) == BODY, (
        f"the positive control must deliver exactly {BODY!r}, got {b''.join(ok_frames)!r}"
    )
    assert "ErrorCode" not in ok_complete, (
        f"the positive control reported ErrorCode {ok_complete.get('ErrorCode')!r} on a handler "
        f"that ran to completion"
    )

    # ---- (2) break exactly one thing: the handler throws before its first write ----
    throw_frames, throw_complete = _stream(lam, fn, "throw")
    assert throw_frames == [], (
        f"a handler that threw before writing must deliver NO payload frames, got {throw_frames!r}"
    )
    assert "ErrorCode" not in throw_complete, (
        f"real AWS reports no ErrorCode on InvokeComplete for a thrown streaming handler, but this "
        f"target reported {throw_complete.get('ErrorCode')!r} (ErrorDetails "
        f"{throw_complete.get('ErrorDetails')!r}) — the response surface must stay silent and the "
        f"log must carry the failure"
    )

    # ...and the throw really happened, with its exact type and message, in the handler's own log.
    throw_errors = _invoke_error_records(throw_complete)
    assert len(throw_errors) == 1, (
        f"the log tail of the thrown invocation must carry exactly one Invoke Error record, got "
        f"{throw_errors!r}"
    )
    assert throw_errors[0]["errorType"] == "Error", (
        f"the logged errorType must be the thrown error's own type 'Error', got "
        f"{throw_errors[0]['errorType']!r}"
    )
    assert throw_errors[0]["errorMessage"] == THROW_MESSAGE, (
        f"the logged errorMessage must be the message the handler threw {THROW_MESSAGE!r}, got "
        f"{throw_errors[0]['errorMessage']!r}"
    )

    # ---- (3) the response surface cannot tell the failure apart from an empty body ----
    silent_frames, silent_complete = _stream(lam, fn, "silent")
    assert silent_frames == [], (
        f"a handler that ended the stream without writing must deliver no frames, got "
        f"{silent_frames!r}"
    )
    assert "ErrorCode" not in silent_complete, (
        f"an empty but successful stream must carry no ErrorCode, got "
        f"{silent_complete.get('ErrorCode')!r}"
    )
    assert _invoke_error_records(silent_complete) == [], (
        f"the deliberately-empty invocation logged an Invoke Error record, so the log does not "
        f"distinguish it from the thrown one either: {_invoke_error_records(silent_complete)!r}"
    )

    # ---- the silence is not an artifact of the event-stream client ----
    buffered_throw = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse",
        Payload=json.dumps({"mode": "throw"}).encode(),
    )
    assert buffered_throw.get("FunctionError") is None, (
        f"Invoke on a streamifyResponse handler that threw must report no FunctionError, got "
        f"{buffered_throw.get('FunctionError')!r}"
    )
    buffered_body = buffered_throw["Payload"].read()
    assert buffered_body == b"", (
        f"Invoke on a streamifyResponse handler that threw must return an empty body, got "
        f"{buffered_body!r}"
    )

    # ---- (4) positive control: the identical throw IS surfaced by a non-streaming handler ----
    plain = ctx.unique_name("sim2real-behav-plainthrow-")
    _create_function(
        ctx, lam,
        FunctionName=plain,
        Runtime="nodejs22.x",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.js": BUFFERED_JS})},
        MemorySize=512,
        Timeout=60,
        Tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    _wait_active(lam, plain)

    surfaced = lam.invoke(FunctionName=plain, InvocationType="RequestResponse", Payload=b"{}")
    assert surfaced["FunctionError"] == "Unhandled", (
        f"a NON-streaming handler throwing the same error must come back with "
        f"FunctionError='Unhandled', got {surfaced.get('FunctionError')!r} — without this control "
        f"the silence asserted above could just be a target that never reports handler errors"
    )
    surfaced_body = json.loads(surfaced["Payload"].read())
    assert surfaced_body["errorType"] == "Error", (
        f"the buffered error envelope must name the thrown type 'Error', got "
        f"{surfaced_body.get('errorType')!r} in {surfaced_body!r}"
    )
    assert surfaced_body["errorMessage"] == THROW_MESSAGE, (
        f"the buffered error envelope must carry the thrown message {THROW_MESSAGE!r}, got "
        f"{surfaced_body.get('errorMessage')!r}"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _stream(lam, fn: str, mode: str):
    """One streaming invoke in `mode`; returns (payload frames in arrival order, InvokeComplete)."""
    resp = lam.invoke_with_response_stream(
        FunctionName=fn,
        InvocationType="RequestResponse",
        LogType="Tail",
        Payload=json.dumps({"mode": mode}).encode(),
    )
    assert resp["StatusCode"] == 200, (
        f"mode={mode!r}: InvokeWithResponseStream returned StatusCode {resp['StatusCode']!r}, "
        f"expected 200 — a thrown handler must not change the transport's status"
    )
    frames: list[bytes] = []
    complete = None
    for event in resp["EventStream"]:
        if "PayloadChunk" in event:
            frames.append(event["PayloadChunk"]["Payload"])
        if "InvokeComplete" in event:
            complete = event["InvokeComplete"]
    assert complete is not None, (
        f"mode={mode!r}: the event stream ended without an InvokeComplete event; frames {frames!r}"
    )
    return frames, complete


def _invoke_error_records(complete: dict) -> list[dict]:
    """The runtime's `Invoke Error` JSON records out of an InvokeComplete log tail.

    Parsed per tab-delimited record, since a substring scan would also match the handler's stdout.
    """
    assert complete.get("LogResult"), (
        f"InvokeComplete carried no LogResult although LogType='Tail' was requested: "
        f"{sorted(complete)!r}"
    )
    tail = base64.b64decode(complete["LogResult"]).decode()
    out: list[dict] = []
    for line in tail.splitlines():
        fields = line.split("\t")
        if len(fields) < 2 or fields[-2].strip() != "Invoke Error":
            continue
        out.append(json.loads(fields[-1]))
    return out


def _execution_role(ctx) -> str:
    """This check's own Lambda execution role."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-strmthrow-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # IAM propagation is absorbed at first use by the deadline-bound retry in _create_function.
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the role-propagation refusal. Raises on deadline.

    The log-group reap is registered first so it runs after delete_function, which keeps the group.
    """
    name = kwargs["FunctionName"]
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidParameterValueException", "ResourceConflictException"):
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"CreateFunction({name}) never succeeded within 120s; last error {last!r}")


def _reap_log_group(ctx, name: str, rounds: int = 6, interval_s: float = 8.0) -> None:
    """Delete /aws/lambda/<name> until it stays gone for two consecutive polls.

    Buffered logs from a finished invocation can flush late and recreate the group after a delete.
    """
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    absent_streak = 0
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
        found = [
            g["logGroupName"]
            for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if g["logGroupName"] == group
        ]
        absent_streak = 0 if found else absent_streak + 1
        if absent_streak >= 2:
            return
    raise RuntimeError(f"log group {group} kept reappearing after {rounds} delete rounds")


def _wait_active(lam, name: str, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Failed":
            raise AssertionError(
                f"{name} entered State=Failed: {last.get('StateReasonCode')!r} "
                f"{last.get('StateReason')!r}"
            )
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(2)
    raise AssertionError(f"{name} never reached State=Active within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
