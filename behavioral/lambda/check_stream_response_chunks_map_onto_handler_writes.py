"""stream-response-chunks-map-onto-handler-writes."""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-response-chunks-map-onto-handler-writes"
GROUP = 'invoke_stream'
SERVICES = ['lambda']

# Deliberately different lengths, so the cumulative write offsets fingerprint any re-chunking.
SEGMENTS = ["alpha|", "bravo-2|", "charlie-33|", "delta-444|"]
BODY = "".join(SEGMENTS).encode()
BOUNDARIES = [len("".join(SEGMENTS[: i + 1])) for i in range(len(SEGMENTS))]
GAP_MS = 900
# The handler's own accumulated sleep, in seconds, not an observed latency.
HANDLER_SLEEP_S = (len(SEGMENTS) - 1) * GAP_MS / 1000.0

HANDLER_JS = """
const { setTimeout: sleep } = require('timers/promises');

const SEGMENTS = %s;
const GAP_MS = %d;

exports.handler = awslambda.streamifyResponse(async (event, responseStream, _context) => {
  for (let i = 0; i < SEGMENTS.length; i++) {
    console.log(`WROTE ${i} ${SEGMENTS[i].length}`);
    responseStream.write(SEGMENTS[i]);
    if (i < SEGMENTS.length - 1) {
      await sleep(GAP_MS);
    }
  }
  responseStream.end();
});
""" % (json.dumps(SEGMENTS), GAP_MS)


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeWithResponseStream frames match the handler's write boundaries, arrive incrementally and
    reassemble in order to the written bytes, agreeing with its log; Invoke returns them as one body.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-response-streaming.html
    """
    lam = ctx.client("lambda")
    role_arn = _execution_role(ctx)

    fn = ctx.unique_name("sim2real-behav-strmchunk-")
    _create_function(
        ctx, lam,
        FunctionName=fn,
        Runtime="nodejs22.x",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip({"index.js": HANDLER_JS})},
        MemorySize=512,
        Timeout=60,
        Tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    _wait_active(lam, fn)

    resp = lam.invoke_with_response_stream(
        FunctionName=fn, InvocationType="RequestResponse", LogType="Tail", Payload=b"{}"
    )
    assert resp["StatusCode"] == 200, (
        f"InvokeWithResponseStream returned StatusCode {resp['StatusCode']!r}, expected 200: {resp!r}"
    )
    assert resp["ResponseStreamContentType"] == "application/vnd.amazon.eventstream", (
        f"the streaming response must be framed as an AWS event stream, got "
        f"ResponseStreamContentType {resp.get('ResponseStreamContentType')!r}"
    )
    assert resp["ExecutedVersion"] == "$LATEST", (
        f"an unqualified streaming invoke must execute $LATEST, got "
        f"ExecutedVersion {resp.get('ExecutedVersion')!r}"
    )

    frames, arrivals, complete = _drain(resp["EventStream"], BODY)

    assert len(frames) >= 2, (
        f"the response arrived in {len(frames)} frame(s), so nothing was streamed: the handler "
        f"issued {len(SEGMENTS)} separate writes {GAP_MS}ms apart and the transport delivered them "
        f"as one blob: {frames!r}"
    )
    offsets = [sum(len(f) for f in frames[: i + 1]) for i in range(len(frames))]
    assert offsets == BOUNDARIES, (
        f"the frame boundaries must coincide with the handler's write boundaries {BOUNDARIES!r} "
        f"(one frame per responseStream.write), got {offsets!r} from frames {frames!r}"
    )
    assert b"".join(frames) == BODY, (
        f"the frames must reassemble to exactly the bytes the handler wrote {BODY!r}, got "
        f"{b''.join(frames)!r}"
    )
    assert complete is not None, (
        f"the event stream ended without an InvokeComplete event; frames were {frames!r}"
    )
    assert "ErrorCode" not in complete, (
        f"a handler that ran to completion must not report an ErrorCode on InvokeComplete, got "
        f"{complete.get('ErrorCode')!r} (ErrorDetails {complete.get('ErrorDetails')!r})"
    )

    # Measured against the handler's own sleep schedule: frames landing within a fraction of it
    # were buffered to completion and then re-framed.
    spread = arrivals[-1] - arrivals[0]
    assert spread >= HANDLER_SLEEP_S / 2.0, (
        f"the first and last frame arrived {spread:.3f}s apart, but the handler sleeps "
        f"{HANDLER_SLEEP_S:.1f}s between its first and last write — the response was buffered to "
        f"completion and then re-framed. Arrivals: {[round(a, 3) for a in arrivals]!r}"
    )

    wrote = _wrote_lines(complete)
    assert wrote == [(i, len(SEGMENTS[i])) for i in range(len(SEGMENTS))], (
        f"the handler's own log must report writing segments 0..{len(SEGMENTS) - 1} with lengths "
        f"{[len(s) for s in SEGMENTS]!r} in order, got {wrote!r}"
    )

    # Control: same function via Invoke must return the same bytes with no framing.
    buffered = lam.invoke(FunctionName=fn, InvocationType="RequestResponse", Payload=b"{}")
    assert buffered.get("FunctionError") is None, (
        f"the control Invoke reported FunctionError {buffered.get('FunctionError')!r}: "
        f"{buffered['Payload'].read()!r}"
    )
    assert "EventStream" not in buffered, (
        f"Invoke must answer with a single buffered Payload, not an event stream: "
        f"{sorted(buffered)!r}"
    )
    body = buffered["Payload"].read()
    assert body == BODY, (
        f"Invoke on the same streaming handler must return the whole stream as one body {BODY!r}, "
        f"got {body!r}"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _drain(event_stream, expected: bytes):
    """Read the event stream, asserting every accumulated prefix is a prefix of `expected`."""
    frames: list[bytes] = []
    arrivals: list[float] = []
    complete = None
    t0 = time.monotonic()
    acc = b""
    for event in event_stream:
        if "PayloadChunk" in event:
            payload = event["PayloadChunk"]["Payload"]
            assert payload, f"an empty PayloadChunk frame arrived after {frames!r}"
            acc += payload
            assert expected.startswith(acc), (
                f"frame {len(frames)} ({payload!r}) does not continue the expected body: bytes so "
                f"far {acc!r} is not a prefix of {expected!r}"
            )
            frames.append(payload)
            arrivals.append(time.monotonic() - t0)
        if "InvokeComplete" in event:
            complete = event["InvokeComplete"]
    return frames, arrivals, complete


def _wrote_lines(complete: dict) -> list[tuple[int, int]]:
    """The (index, length) pairs the handler itself logged, in the order it logged them.

    Only handler records are read: START/END/REPORT ordering relative to handler stdout is not fixed.
    """
    assert complete.get("LogResult"), (
        f"InvokeComplete carried no LogResult although LogType='Tail' was requested: "
        f"{sorted(complete)!r}"
    )
    tail = base64.b64decode(complete["LogResult"]).decode()
    out: list[tuple[int, int]] = []
    for line in tail.splitlines():
        fields = line.split("\t")
        message = fields[-1].strip()
        if not message.startswith("WROTE "):
            continue
        _, index, length = message.split()
        out.append((int(index), int(length)))
    assert out, f"the handler logged no WROTE records at all; whole tail was {tail!r}"
    return out


def _execution_role(ctx) -> str:
    """This check's own Lambda execution role."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-strmchunk-role-")
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
    # IAM propagation exposes no condition to poll; the bounded retry in _create_function
    # rides it out on first use.
    return role["Role"]["Arn"]


def _create_function(ctx, lam, **kwargs):
    """CreateFunction, retrying only the role-propagation refusal. Raises on deadline."""
    name = kwargs["FunctionName"]
    # Registered first so LIFO runs it after delete_function, which leaves /aws/lambda/<fn> behind.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    timeout_s = 120.0
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 30.0))
    deadline = time.monotonic() + timeout_s
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
    raise AssertionError(
        f"CreateFunction({name}) never succeeded within {timeout_s:.0f}s; last error {last!r}"
    )


def _reap_log_group(ctx, name: str, rounds: int = 6, interval_s: float = 8.0) -> None:
    """Delete /aws/lambda/<name> until two consecutive polls find it absent.

    A buffered log stream from a finished invocation can recreate the group after a delete.
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
