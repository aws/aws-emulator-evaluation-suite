"""provided-al2023-bootstrap-serves-the-runtime-api."""

from __future__ import annotations

import base64
import json
import time
import zipfile
import io

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "provided-al2023-bootstrap-serves-the-runtime-api"
GROUP = 'data-plane'
SERVICES = ['lambda']

RUNTIME_API_VERSION = "2018-06-01"

# A custom runtime that drives the Lambda runtime API itself, with no toolchain at all: /bin/sh and
# /usr/bin/curl, both present inside provided.al2023. The loop is the contract: long-poll `next`,
# take the request id from the RESPONSE HEADER, and address the reply to that id. Everything the check asserts is something the bootstrap read out of the runtime API and
# reported back through it.
#
# Three payload-selected arms, so one function exercises all three directions of the interface:
#   default        -> POST .../response
#   {"fail":true}  -> POST .../error with a custom errorType
#   {"badId":true} -> POST .../response addressed to an id that was never handed out, capture the
#                     refusal, then reply correctly to the real id and report what happened
#
# /tmp/probe-markers/<request-id> is written only on the success path. A bootstrap process keeps
# that directory across the invocations it serves, so it is state across time inside the sandbox,
# and the failed invocation's absence from it is the effect-absent probe. Lambda may recycle an
# environment at any time, so the bootstrap reports a per-process boot id and the loop counter,
# previous POST status and markers are graded per boot.
BOOTSTRAP = r'''#!/bin/sh
set -u
API="http://$AWS_LAMBDA_RUNTIME_API/''' + RUNTIME_API_VERSION + r'''/runtime/invocation"
BOGUS_ID="deadbeef-0000-0000-0000-000000000000"
MARKERS=/tmp/probe-markers
mkdir -p "$MARKERS"
BOOT=$(cat /proc/sys/kernel/random/uuid)
LOOP=0
PREV_POST=none
BAD_STATUS=none
BAD_BODY=null
echo "PROBE-BOOT curl=$(command -v curl) api=$AWS_LAMBDA_RUNTIME_API"
while true; do
  LOOP=$((LOOP + 1))
  HDR=/tmp/probe-hdr
  BODY=/tmp/probe-body
  curl -sS -D "$HDR" -o "$BODY" "$API/next"
  RID=$(grep -i '^lambda-runtime-aws-request-id:' "$HDR" | tr -d '\r' | sed 's/^[^:]*: *//')
  DEADLINE=$(grep -i '^lambda-runtime-deadline-ms:' "$HDR" | tr -d '\r' | sed 's/^[^:]*: *//')
  ARN=$(grep -i '^lambda-runtime-invoked-function-arn:' "$HDR" | tr -d '\r' | sed 's/^[^:]*: *//')
  INVID=$(grep -i '^lambda-runtime-invocation-id:' "$HDR" | tr -d '\r' | sed 's/^[^:]*: *//')
  echo "PROBE-NEXT boot=$BOOT loop=$LOOP rid=$RID"
  if grep -q '"fail"' "$BODY"; then
    echo "PROBE-ERROR-PATH rid=$RID"
    curl -sS -o /dev/null -X POST \
      -d '{"errorMessage":"probe custom failure","errorType":"probe.CustomError"}' \
      "$API/$RID/error"
    continue
  fi
  if grep -q '"badId"' "$BODY"; then
    BAD_STATUS=$(curl -sS -o /tmp/probe-bad -w '%{http_code}' -X POST -d '{"stolen":true}' \
      "$API/$BOGUS_ID/response")
    BAD_BODY=$(cat /tmp/probe-bad)
    echo "PROBE-BAD-ID status=$BAD_STATUS body=$BAD_BODY"
  fi
  : > "$MARKERS/$RID"
  MK=$(ls "$MARKERS" | sort | tr '\n' ',')
  PAYLOAD="{\"echoedRequestId\":\"$RID\",\"invocationId\":\"$INVID\",\"deadlineMs\":$DEADLINE,\
\"invokedArn\":\"$ARN\",\"boot\":\"$BOOT\",\"loop\":$LOOP,\"prevPostStatus\":\"$PREV_POST\",\"markers\":\"$MK\",\
\"badIdStatus\":\"$BAD_STATUS\",\"badIdBody\":$BAD_BODY,\"eventEcho\":$(cat "$BODY")}"
  PREV_POST=$(curl -sS -o /dev/null -w '%{http_code}' -X POST -d "$PAYLOAD" "$API/$RID/response")
done
'''


# ===== helpers =====
def _zip_bootstrap(script):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("bootstrap")
        info.external_attr = 0o755 << 16
        zf.writestr(info, script)
    return buf.getvalue()


# A bootstrap that starts and exits without ever polling `next`. This, NOT a missing executable
# bit, is what real AWS reports as Runtime.ExitError: provided.al2023 launches a `bootstrap` whose
# zip entry carries mode 0644, so the platform enforces only that the runtime answers the API.
SILENT_BOOTSTRAP = "#!/bin/sh\nexit 0\n"


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
    try:
        # Deleting the function deletes every published version and any snapshot with it.
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # /aws/lambda/<fn> is created by the service, and buffered log delivery can recreate it after a
    # successful delete_log_group, so require a sustained absence.
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    absent = 0
    for _ in range(20):
        present = any(
            g["logGroupName"] == group
            for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        )
        if present:
            absent = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= 3:
                return
        time.sleep(3)
    raise RuntimeError(f"log group {group} still reappearing after 20 delete passes")


def _poll(probe, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=300):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')!r}")
        if cfg["State"] == "Active" and cfg.get("LastUpdateStatus") in (None, "Successful"):
            return cfg
        return None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _create(ctx, lam, fn, zb, timeout=30):
    _create_function(lam,
        FunctionName=fn, Runtime="provided.al2023", Handler="bootstrap",
        Role=_role_arn(ctx), Code={"ZipFile": zb}, MemorySize=512, Timeout=timeout,
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    return _wait_active(lam, fn)


def _invoke(lam, fn, payload):
    resp = lam.invoke(FunctionName=fn, LogType="Tail", Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{fn}: StatusCode {resp['StatusCode']!r} {raw!r}"
    log = base64.b64decode(resp["LogResult"]).decode("utf8", "replace")
    return {
        "err": resp.get("FunctionError"),
        "body": json.loads(raw),
        "log": log,
        "request_id": resp["ResponseMetadata"]["RequestId"],
    }


def _next_loop(loops, boot, loop, label):
    """Within one bootstrap process the loop counter climbs 1, 2, ... one per invocation served."""
    seen = loops.setdefault(boot, [])
    assert loop == len(seen) + 1, (
        f"{label}: bootstrap process {boot} reported loop {loop!r} after serving loops {seen!r}; "
        f"one process counts every invocation it is handed, error path included"
    )
    seen.append(loop)


def _prev_post(wins, body):
    """The previous response POST status is 202 once this process has answered an invocation."""
    want = "202" if wins.get(body["boot"]) else "none"
    assert body["prevPostStatus"] == want, (
        f"bootstrap process {body['boot']} reports {body['prevPostStatus']!r} for its PREVIOUS "
        f"POST to .../response, expected {want!r}; Invocation response answers 202 Accepted"
    )


def _win(wins, all_wins, body):
    """Record a success; the process's markers hold its own successes and only successes."""
    rid = body["echoedRequestId"]
    wins.setdefault(body["boot"], []).append(rid)
    all_wins.add(rid)
    mine = set(wins[body["boot"]])
    assert mine <= _markers(body) <= all_wins, (
        f"bootstrap process {body['boot']} holds markers {sorted(_markers(body))!r}; it must hold "
        f"every request id it answered {sorted(mine)!r} and nothing but successful ones "
        f"{sorted(all_wins)!r}"
    )


def _markers(body):
    return {m for m in body["markers"].split(",") if m}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A provided.al2023 bootstrap process serves successive invocations (counted per boot id) over
    the runtime API, which routes by request id and propagates a custom error verbatim; a bootstrap that never polls
    `next` is accepted at create and fails at invoke as Runtime.ExitError in the INIT phase."""
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-al2023boot-")
    cfg = _create(ctx, lam, fn, _zip_bootstrap(BOOTSTRAP))
    arn = cfg["FunctionArn"]

    # ---- invocation 1: the runtime API handed the bootstrap a real invocation --------------
    before_ms = int(time.time() * 1000)
    one = _invoke(lam, fn, {"probe": "first"})
    after_ms = int(time.time() * 1000)
    assert one["err"] is None, f"the first invocation failed: {one['err']!r} {one['body']!r}"
    b1 = one["body"]

    assert b1["echoedRequestId"] == one["request_id"], (
        f"the bootstrap read request id {b1['echoedRequestId']!r} from the "
        f"Lambda-Runtime-Aws-Request-Id header on `next`, but the caller's Invoke response carries "
        f"{one['request_id']!r}. The runtime API must hand the runtime the SAME invocation "
        f"identifier the caller was given"
    )
    assert b1["invokedArn"] == arn, (
        f"Lambda-Runtime-Invoked-Function-Arn was {b1['invokedArn']!r}, but GetFunction reports "
        f"{arn!r}"
    )
    assert isinstance(b1["deadlineMs"], int), (
        f"Lambda-Runtime-Deadline-Ms was not an integer: {b1['deadlineMs']!r}"
    )
    assert before_ms < b1["deadlineMs"] <= after_ms + 30_000 + 5_000, (
        f"Lambda-Runtime-Deadline-Ms {b1['deadlineMs']!r} is not a live wall-clock deadline inside "
        f"the configured Timeout=30s window [{before_ms}, {after_ms + 35_000}] — a constant or a "
        f"zero passes no version of this"
    )
    assert b1["invocationId"] and b1["invocationId"] != b1["echoedRequestId"], (
        f"Lambda-Runtime-Invocation-Id must be present and distinct from the request id; got "
        f"{b1['invocationId']!r} and {b1['echoedRequestId']!r}"
    )
    assert b1["eventEcho"] == {"probe": "first"}, (
        f"the body the bootstrap read from `next` was {b1['eventEcho']!r}, not the payload the "
        f"caller sent"
    )
    assert b1["loop"] == 1 and b1["prevPostStatus"] == "none", (
        f"the first invocation should be the bootstrap's first loop iteration with no previous "
        f"response POST: loop={b1['loop']!r} prevPostStatus={b1['prevPostStatus']!r}"
    )
    assert "PROBE-BOOT curl=/usr/bin/curl" in one["log"], (
        f"the bootstrap's own start-up line is missing, so it is not the process being observed: "
        f"{one['log'][:400]!r}"
    )

    loops = {b1["boot"]: [1]}                    # boot id -> loop counters it reported, in order
    wins = {b1["boot"]: [b1["echoedRequestId"]]}   # boot id -> its successful request ids
    all_wins = {b1["echoedRequestId"]}

    # ---- invocation 2: a bootstrap process serves successive invocations -------------------
    two = _invoke(lam, fn, {"probe": "second"})
    assert two["err"] is None, f"the second invocation failed: {two['err']!r} {two['body']!r}"
    b2 = two["body"]
    _next_loop(loops, b2["boot"], b2["loop"], "the second invocation")
    _prev_post(wins, b2)
    assert b2["echoedRequestId"] == two["request_id"] != b1["echoedRequestId"], (
        f"the second invocation's ids are wrong: bootstrap saw {b2['echoedRequestId']!r}, caller "
        f"{two['request_id']!r}, first invocation {b1['echoedRequestId']!r}"
    )
    assert b2["deadlineMs"] > b1["deadlineMs"], (
        f"the second invocation's deadline {b2['deadlineMs']!r} is not later than the first's "
        f"{b1['deadlineMs']!r} — the deadline is per-invocation, not a constant baked into the "
        f"environment"
    )
    _win(wins, all_wins, b2)

    # ---- the error path: a custom runtime's error identity reaches the caller verbatim -----
    bad = _invoke(lam, fn, {"fail": True})
    assert bad["err"] == "Unhandled", (
        f"POSTing to .../invocation/<id>/error must surface to the caller as FunctionError="
        f"'Unhandled'; got {bad['err']!r} with payload {bad['body']!r}"
    )
    assert bad["body"]["errorType"] == "probe.CustomError", (
        f"errorType was {bad['body'].get('errorType')!r}. The platform must propagate the exact "
        f"errorType the custom runtime posted — 'probe.CustomError' is a string no AWS component "
        f"could invent"
    )
    assert bad["body"]["errorMessage"] == "probe custom failure", (
        f"errorMessage was {bad['body'].get('errorMessage')!r}, not the body the runtime posted"
    )
    assert f"PROBE-ERROR-PATH rid={bad['request_id']}" in bad["log"], (
        f"the bootstrap did not take its error branch for request {bad['request_id']!r}: "
        f"{bad['log'][-600:]!r}"
    )
    # The error path consumes a loop iteration without POSTing a response.
    nxt = [ln[ln.index("PROBE-NEXT "):].split() for ln in bad["log"].splitlines()
           if "PROBE-NEXT " in ln and ln.rstrip().endswith(f" rid={bad['request_id']}")]
    assert len(nxt) == 1, (
        f"the bootstrap must log one PROBE-NEXT line for request {bad['request_id']!r}: "
        f"{bad['log'][-600:]!r}"
    )
    fields = dict(tok.split("=", 1) for tok in nxt[0][1:])
    _next_loop(loops, fields["boot"], int(fields["loop"]), "the error-path invocation")

    # ---- request-id routing, plus the effect-absent probe on the failed invocation ---------
    # Markers are written only on the success path and one process owns /tmp across invocations,
    # so the failed invocation's id must be absent from the accumulated set.
    three = _invoke(lam, fn, {"badId": True})
    assert three["err"] is None, (
        f"the invocation whose runtime posted one reply to a bogus id and one to the real id did "
        f"not succeed: {three['err']!r} {three['body']!r}"
    )
    b3 = three["body"]
    assert b3["badIdStatus"] == "400", (
        f"a response POSTed to an invocation id that was never handed out was answered HTTP "
        f"{b3['badIdStatus']!r}; the runtime API routes strictly by request id and must refuse it "
        f"with 400"
    )
    assert b3["badIdBody"]["errorType"] == "InvalidRequestID", (
        f"the refusal body was {b3['badIdBody']!r}; real AWS returns errorType 'InvalidRequestID' "
        f"for this case"
    )
    assert b3["badIdBody"]["errorMessage"] == "Invalid request ID", (
        f"the refusal errorMessage was {b3['badIdBody'].get('errorMessage')!r}"
    )
    # The correctly-addressed reply in the SAME invocation still worked: the refusal was scoped to
    # the bogus id, not to the connection or the invocation.
    assert b3["echoedRequestId"] == three["request_id"], (
        f"the reply addressed to the real id did not come back to the caller: "
        f"{b3['echoedRequestId']!r} vs {three['request_id']!r}"
    )
    _next_loop(loops, b3["boot"], b3["loop"], "the bad-id invocation")
    _prev_post(wins, b3)
    assert bad["request_id"] not in _markers(b3), (
        f"the failed invocation's request id {bad['request_id']!r} appears in the bootstrap's "
        f"success-path marker set {sorted(_markers(b3))!r} — the success path ran for an invocation "
        f"that was reported as an error"
    )
    _win(wins, all_wins, b3)

    # ---- the obligation half: a runtime that never answers `next` is a runtime failure ------
    # The platform cannot know at CreateFunction whether a bootstrap will speak the protocol, so a
    # runtime that starts and exits is accepted, then attributed to the RUNTIME at invoke.
    silent = ctx.unique_name("sim2real-behav-al2023silent-")
    silent_cfg = _create(ctx, lam, silent, _zip_bootstrap(SILENT_BOOTSTRAP))
    assert silent_cfg["State"] == "Active", (
        f"whether a bootstrap answers the runtime API is unknowable to the control plane, so "
        f"CreateFunction must still reach State=Active; it reported {silent_cfg['State']!r} "
        f"{silent_cfg.get('StateReason')!r}"
    )
    ne = _invoke(lam, silent, {"probe": "silent"})
    assert ne["err"] == "Unhandled", (
        f"invoking a bootstrap that never polls .../invocation/next returned "
        f"FunctionError={ne['err']!r} {ne['body']!r}; it must not look like a success"
    )
    assert ne["body"]["errorType"] == "Runtime.ExitError", (
        f"errorType was {ne['body'].get('errorType')!r}; real AWS attributes this to the runtime "
        f"exiting (Runtime.ExitError, not Runtime.InvalidEntrypoint)"
    )
    assert ne["body"]["errorMessage"] == (
        f"RequestId: {ne['request_id']} Error: Runtime exited without providing a reason"
    ), f"errorMessage was {ne['body'].get('errorMessage')!r}"
    assert "PROBE-BOOT" not in ne["log"], (
        f"the silent bootstrap printed the polling runtime's start-up line, so the two deployment "
        f"packages are not the ones this arm intends to contrast: {ne['log'][:400]!r}"
    )
    init_report = [ln for ln in ne["log"].splitlines() if ln.startswith("INIT_REPORT")]
    assert any("Phase: init" in ln and "Status: error" in ln for ln in init_report), (
        f"the failure must be recorded against the INIT phase, because the runtime died before any "
        f"invocation was handed to it; INIT_REPORT lines were {init_report!r}"
    )
    assert lam.get_function_configuration(FunctionName=silent)["State"] == "Active", (
        f"the function left State=Active after the invoke failed; a runtime that does not speak the "
        f"protocol is not a function-state transition"
    )

    # ---- control: the good function still serves after everything above --------------------
    last = _invoke(lam, fn, {"probe": "last"})
    assert last["err"] is None, (
        f"the working custom runtime stopped serving: {last['err']!r} {last['body']!r}"
    )
    _next_loop(loops, last["body"]["boot"], last["body"]["loop"], "the last invocation")
    assert any(len(v) > 1 for v in loops.values()), (
        f"every invocation reported a new bootstrap process {loops!r}; reusing one process across "
        f"invocations is the purpose of the poll-based runtime API"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
