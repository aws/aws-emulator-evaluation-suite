"""stream-provisioned-streaming-function-streams-from-prewarmed-environment."""

from __future__ import annotations

import base64
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-provisioned-streaming-function-streams-from-prewarmed-environment"
GROUP = 'concurrency'
SERVICES = ['lambda']

PROVISIONED = 1
SEGMENTS = ["tail-0|", "tail-1-x|", "tail-2-yy|"]
TAIL_BODY = "".join(SEGMENTS).encode()
GAP_MS = 700
# The handler's own accumulated sleep between its first and last write, in seconds.
HANDLER_SLEEP_S = len(SEGMENTS) * GAP_MS / 1000.0

# The first thing the handler streams is its own account of the environment it is running in:
# AWS_LAMBDA_INITIALIZATION_TYPE is injected by the execution environment, and the per-environment
# id is minted once at module scope. Both travel out through the response stream itself.
HANDLER_JS = """
const { setTimeout: sleep } = require('timers/promises');
const crypto = require('crypto');

const SEGMENTS = %s;
const GAP_MS = %d;
const ENV_ID = crypto.randomUUID();

exports.handler = awslambda.streamifyResponse(async (event, responseStream, context) => {
  const head = JSON.stringify({
    env_id: ENV_ID,
    init_type: process.env.AWS_LAMBDA_INITIALIZATION_TYPE,
    version: context.functionVersion,
  }) + '\\n';
  console.log('HEAD ' + head.trim());
  responseStream.write(head);
  for (let i = 0; i < SEGMENTS.length; i++) {
    await sleep(GAP_MS);
    console.log(`WROTE ${i}`);
    responseStream.write(SEGMENTS[i]);
  }
  responseStream.end();
});
""" % (json.dumps(SEGMENTS), GAP_MS)


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c6", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A provisioned version still streams frame by frame and reports initialization type
    'provisioned-concurrency' from a reused environment, while $LATEST reports 'on-demand'.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-response-streaming.html
    """
    lam = ctx.client("lambda")
    role_arn = _execution_role(ctx)

    fn = ctx.unique_name("sim2real-behav-pcstream-")
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

    version = lam.publish_version(FunctionName=fn)["Version"]
    _wait_active(lam, f"{fn}:{version}")

    # Provisioned concurrency BILLS FROM THE MOMENT IT IS READY, so the delete is registered before
    # the readiness poll — not after it — or a poll that times out leaks a live charge.
    lam.put_provisioned_concurrency_config(
        FunctionName=fn, Qualifier=version, ProvisionedConcurrentExecutions=PROVISIONED
    )
    ctx.on_cleanup(
        lambda: lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=version)
    )

    # ---- leg 1: $LATEST, nothing pre-warmed it ----
    cold = _stream(lam, fn)
    assert cold["head"]["init_type"] == "on-demand", (
        f"a streaming invocation of $LATEST, which no provisioned concurrency config covers, must "
        f"report AWS_LAMBDA_INITIALIZATION_TYPE='on-demand' in its first frame, got "
        f"{cold['head']!r}"
    )
    assert cold["head"]["version"] == "$LATEST", (
        f"an unqualified streaming invoke must execute $LATEST, handler reported "
        f"{cold['head']['version']!r}"
    )
    assert cold["executed_version"] == "$LATEST", (
        f"ExecutedVersion must be $LATEST for an unqualified streaming invoke, got "
        f"{cold['executed_version']!r}"
    )

    pc = _wait_provisioned_ready(lam, fn, version)
    requested = pc["RequestedProvisionedConcurrentExecutions"]
    assert pc["AvailableProvisionedConcurrentExecutions"] == requested, (
        f"Status=READY was reported but only "
        f"{pc['AvailableProvisionedConcurrentExecutions']!r} of {requested!r} provisioned "
        f"executions are available: {pc!r}"
    )

    # ---- leg 2: the same code on the provisioned version — pre-warmed AND still streaming ----
    warm = _stream(lam, fn, qualifier=version)
    assert warm["head"]["init_type"] == "provisioned-concurrency", (
        f"a streaming invocation served by a READY provisioned environment must report "
        f"AWS_LAMBDA_INITIALIZATION_TYPE='provisioned-concurrency' in its first frame, got "
        f"{warm['head']!r} — the environment was not pre-warmed, whatever the control plane said"
    )
    assert warm["head"]["version"] == version, (
        f"the qualified streaming invoke must execute version {version!r}, handler reported "
        f"{warm['head']['version']!r}"
    )
    assert warm["executed_version"] == version, (
        f"ExecutedVersion must be {version!r} for a qualified streaming invoke, got "
        f"{warm['executed_version']!r}"
    )
    assert warm["head"]["env_id"] != cold["head"]["env_id"], (
        f"the provisioned version's environment and $LATEST's cannot be the same process, both "
        f"reported env_id {warm['head']['env_id']!r}"
    )
    # Pre-warming must not have turned the stream into a buffered blob: the frames still land on the
    # handler's write boundaries and still arrive spread across its own sleep schedule.
    assert warm["spread"] >= HANDLER_SLEEP_S / 2.0, (
        f"the provisioned invocation's first and last frame arrived {warm['spread']:.3f}s apart, "
        f"but the handler sleeps {HANDLER_SLEEP_S:.1f}s across its writes — a pre-warmed "
        f"environment buffered the response instead of streaming it. Arrivals: "
        f"{warm['arrivals']!r}"
    )

    # ---- leg 3: the pre-warmed environment is reused, so leg 2 was not a fast cold start ----
    warm2 = _stream(lam, fn, qualifier=version)
    assert warm2["head"]["env_id"] == warm["head"]["env_id"], (
        f"a second streaming invocation of the provisioned version must land in the same "
        f"pre-warmed environment, got {warm2['head']['env_id']!r} after "
        f"{warm['head']['env_id']!r}"
    )
    assert warm2["head"]["init_type"] == "provisioned-concurrency", (
        f"the reused provisioned environment must still report 'provisioned-concurrency', got "
        f"{warm2['head']!r}"
    )

    # ---- leg 4: the absence — provisioning is bounded to the qualifier that was provisioned ----
    after = _stream(lam, fn)
    assert after["head"]["init_type"] == "on-demand", (
        f"$LATEST has no provisioned concurrency config, so a streaming invocation of it must "
        f"still report 'on-demand' after the version was provisioned; got {after['head']!r}"
    )
    assert after["head"]["env_id"] != warm["head"]["env_id"], (
        f"the provisioned environment belongs to version {version!r} alone, but a $LATEST "
        f"streaming invocation was served by it: both reported env_id "
        f"{warm['head']['env_id']!r}"
    )


def _make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _stream(lam, fn: str, qualifier: str | None = None) -> dict:
    """One streaming invoke, graded for framing, byte-exactness, order, and log agreement."""
    kwargs = {
        "FunctionName": fn,
        "InvocationType": "RequestResponse",
        "LogType": "Tail",
        "Payload": b"{}",
    }
    if qualifier is not None:
        kwargs["Qualifier"] = qualifier
    resp = lam.invoke_with_response_stream(**kwargs)
    label = f"{fn}:{qualifier or '$LATEST'}"
    assert resp["StatusCode"] == 200, (
        f"{label}: InvokeWithResponseStream returned StatusCode {resp['StatusCode']!r}, expected 200"
    )
    assert resp["ResponseStreamContentType"] == "application/vnd.amazon.eventstream", (
        f"{label}: the streaming response must be framed as an AWS event stream, got "
        f"ResponseStreamContentType {resp.get('ResponseStreamContentType')!r}"
    )

    frames: list[bytes] = []
    arrivals: list[float] = []
    complete = None
    t0 = time.monotonic()
    for event in resp["EventStream"]:
        if "PayloadChunk" in event:
            payload = event["PayloadChunk"]["Payload"]
            assert payload, f"{label}: an empty PayloadChunk frame arrived after {frames!r}"
            frames.append(payload)
            arrivals.append(time.monotonic() - t0)
        if "InvokeComplete" in event:
            complete = event["InvokeComplete"]

    assert complete is not None, (
        f"{label}: the event stream ended without an InvokeComplete event; frames {frames!r}"
    )
    assert "ErrorCode" not in complete, (
        f"{label}: the handler ran to completion, so InvokeComplete must carry no ErrorCode, got "
        f"{complete.get('ErrorCode')!r} (ErrorDetails {complete.get('ErrorDetails')!r})"
    )
    assert len(frames) == len(SEGMENTS) + 1, (
        f"{label}: the handler issued {len(SEGMENTS) + 1} separate writes (one head plus "
        f"{len(SEGMENTS)} segments), so the response must arrive in that many frames; got "
        f"{len(frames)}: {frames!r}"
    )
    assert frames[1:] == [s.encode() for s in SEGMENTS], (
        f"{label}: each frame after the head must be exactly one of the handler's writes "
        f"{SEGMENTS!r}, got {frames[1:]!r}"
    )
    assert frames[0].endswith(b"\n"), (
        f"{label}: the head frame must be the newline-terminated JSON the handler wrote first, got "
        f"{frames[0]!r}"
    )
    assert b"".join(frames) == frames[0] + TAIL_BODY, (
        f"{label}: the frames must reassemble to the head followed by {TAIL_BODY!r}, got "
        f"{b''.join(frames)!r}"
    )
    head = json.loads(frames[0])
    assert sorted(head) == ["env_id", "init_type", "version"], (
        f"{label}: the streamed head must carry the handler's environment report, got {head!r}"
    )

    logged = _logged_head(complete, label)
    assert logged == head, (
        f"{label}: the streamed head and the handler's own stdout disagree: streamed {head!r}, "
        f"printed {logged!r}"
    )
    wrote = _wrote_indices(complete)
    assert wrote == list(range(len(SEGMENTS))), (
        f"{label}: the handler must log writing segments 0..{len(SEGMENTS) - 1} in order, got "
        f"{wrote!r}"
    )

    return {
        "head": head,
        "frames": frames,
        "arrivals": [round(a, 3) for a in arrivals],
        "spread": arrivals[-1] - arrivals[0],
        "executed_version": resp.get("ExecutedVersion"),
    }


def _tail(complete: dict, label: str = "") -> str:
    assert complete.get("LogResult"), (
        f"{label}: InvokeComplete carried no LogResult although LogType='Tail' was requested: "
        f"{sorted(complete)!r}"
    )
    return base64.b64decode(complete["LogResult"]).decode()


def _logged_head(complete: dict, label: str) -> dict:
    """The environment report the handler printed, parsed off its own log record."""
    records = []
    for line in _tail(complete, label).splitlines():
        message = line.split("\t")[-1].strip()
        if message.startswith("HEAD "):
            records.append(json.loads(message[len("HEAD "):]))
    assert len(records) == 1, (
        f"{label}: the handler must print exactly one HEAD record per invocation, got {records!r}"
    )
    return records[0]


def _wrote_indices(complete: dict) -> list[int]:
    """The segment indices the handler logged, in the order it logged them."""
    out = []
    for line in _tail(complete).splitlines():
        message = line.split("\t")[-1].strip()
        if message.startswith("WROTE "):
            out.append(int(message.split()[1]))
    assert out, "the handler logged no WROTE records at all"
    return out


def _wait_provisioned_ready(lam, fn: str, qualifier: str, timeout_s: float = 600.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_provisioned_concurrency_config(FunctionName=fn, Qualifier=qualifier)
        if last["Status"] == "FAILED":
            raise AssertionError(
                f"provisioned concurrency for {fn}:{qualifier} went to FAILED: "
                f"{last.get('StatusReason')!r}"
            )
        if last["Status"] == "READY":
            return last
        time.sleep(5)
    raise AssertionError(
        f"provisioned concurrency for {fn}:{qualifier} never became READY within {timeout_s}s; "
        f"last={last!r}"
    )


def _execution_role(ctx) -> str:
    """This check's own execution role. Nothing pre-existing in the account is assumed."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-pcstream-role-")
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
    """CreateFunction, retrying only the role-propagation refusal. Raises on deadline.

    The log-group reap is registered BEFORE the create, so LIFO runs it AFTER delete_function:
    delete_function does not remove /aws/lambda/<fn>, and a stream buffered by an invocation that
    already returned can recreate the group after a single delete.
    """
    name = kwargs["FunctionName"]
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
    """Delete /aws/lambda/<name> until it stays gone for two consecutive polls.

    A stream buffered by an invocation that already returned can flush and recreate the group.
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
