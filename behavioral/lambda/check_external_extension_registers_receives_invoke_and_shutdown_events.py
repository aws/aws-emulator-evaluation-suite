"""external-extension-registers-receives-invoke-and-shutdown-events."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "external-extension-registers-receives-invoke-and-shutdown-events"
GROUP = 'extensions_runtime'
SERVICES = ['lambda']

EXT_NAME = "sim2real-probe"
FN_TIMEOUT_S = 5

# The external extension, shipped as an executable under extensions/ in a layer. Stdlib only:
# nothing is fetched and the whole thing is built in-check.
EXTENSION_SRC = '''\
#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

API = os.environ["AWS_LAMBDA_RUNTIME_API"]
LOG = "/tmp/sim2real-ext.log"
NAME = os.path.basename(__file__)


def _append(rec):
    with open(LOG, "a") as fh:
        fh.write(json.dumps(rec) + "\\n")
        fh.flush()
    # Extension stdout is captured into the function's log stream, which is the only instrument
    # that survives a SHUTDOWN.
    print("EXT_REC " + json.dumps(rec), flush=True)


def main():
    req = urllib.request.Request(
        "http://%s/2020-01-01/extension/register" % API,
        data=json.dumps({"events": ["INVOKE", "SHUTDOWN"]}).encode(),
        headers={"Lambda-Extension-Name": NAME, "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req) as r:
        ident = r.headers.get("Lambda-Extension-Identifier")
        body = json.loads(r.read().decode())
    _append({"kind": "register", "identifier": ident, "body": body, "pid": os.getpid()})
    while True:
        nxt = urllib.request.Request(
            "http://%s/2020-01-01/extension/event/next" % API,
            headers={"Lambda-Extension-Identifier": ident})
        with urllib.request.urlopen(nxt) as r:
            ev = json.loads(r.read().decode())
        if ev.get("eventType") == "SHUTDOWN":
            _append({"kind": "EXT_SHUTDOWN", "event": ev, "identifier": ident})
            sys.exit(0)
        _append({"kind": "invoke", "event": ev, "identifier": ident, "pid": os.getpid()})


main()
'''

# The handler reports the extension's own records, read out of the /tmp the two processes share,
# so the check sees the extension's view from INSIDE the same execution environment.
HANDLER_SRC = '''\
import json
import os
import time
import uuid

ENV_ID = str(uuid.uuid4())
INIT_PID = os.getpid()
INIT_COUNT = 0
INIT_COUNT += 1
INVOKE_COUNT = 0
EXT_LOG = "/tmp/sim2real-ext.log"


def _read(request_id, budget_s=3.0):
    """Bounded poll for the extension's record of THIS invocation, keyed on the request id rather
    than on a count so a surviving /tmp cannot satisfy it with a stale record. The check asserts
    the records, so a poll that runs out ends as a failure rather than a soft pass."""
    deadline = time.time() + budget_s
    recs = []
    while True:
        recs = []
        if os.path.exists(EXT_LOG):
            with open(EXT_LOG) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        recs.append(json.loads(line))
        if any(r["kind"] == "invoke" and r["event"].get("requestId") == request_id
               for r in recs):
            return recs
        if time.time() >= deadline:
            return recs
        time.sleep(0.1)


def handler(event, context):
    global INVOKE_COUNT
    INVOKE_COUNT += 1
    if event.get("hang"):
        time.sleep(600)
    recs = _read(context.aws_request_id)
    return {
        "env_id": ENV_ID,
        "init_count": INIT_COUNT,
        "invoke_count": INVOKE_COUNT,
        "handler_pid": os.getpid(),
        "log_stream": context.log_stream_name,
        "request_id": context.aws_request_id,
        "now_ms": time.time() * 1000.0,
        "ext_log_exists": os.path.exists(EXT_LOG),
        "ext_records": recs,
    }
'''


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _make_extension_layer_zip(src):
    """extensions/<name>, mode 0o755. ZipFile.writestr defaults to mode 0, and Lambda silently
    skips a non-executable extension — so the external_attr is load-bearing."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo(f"extensions/{EXT_NAME}")
        info.external_attr = 0o755 << 16
        zf.writestr(info, src)
    return buf.getvalue()


_EXEC_ROLES: dict = {}


def _exec_role_arn(ctx):
    """Execution role this check creates for its functions, once per run."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached and cached[0] is ctx:
        return cached[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function_retrying(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role propagates to Lambda."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as e:
            err = e.response.get("Error", {})
            if (err.get("Code") == "InvalidParameterValueException"
                    and "cannot be assumed by Lambda" in err.get("Message", "")
                    and time.monotonic() < deadline):
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
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_ready(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn} entered Failed: {last.get('StateReason')!r}")
        if last["State"] == "Active" and last.get("LastUpdateStatus") in (None, "Successful"):
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} never became Active in {timeout_s}s; last={last!r}")


def _invoke(lam, fn, payload, *, tail=False):
    kwargs = {"LogType": "Tail"} if tail else {}
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(), **kwargs
    )
    raw = resp["Payload"].read()
    out = {"function_error": resp.get("FunctionError"), "raw": raw}
    if tail:
        import base64
        out["log"] = base64.b64decode(resp["LogResult"]).decode("utf-8", "replace")
    if not resp.get("FunctionError"):
        assert raw, f"{fn} returned an empty payload: {resp!r}"
        out["body"] = json.loads(raw)
    return out


def _records(body, kind):
    return [r for r in body["ext_records"] if r["kind"] == kind]


def _ext_shutdown_records(tail):
    out = []
    for line in tail.splitlines():
        marker = "EXT_REC "
        idx = line.find(marker)
        if idx < 0:
            continue
        rec = json.loads(line[idx + len(marker):])
        if rec["kind"] == "EXT_SHUTDOWN":
            out.append(rec)
    return out


@tags("axis:happy-path", "cap:c3", "cap:c5", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An external extension in a layer registers once per environment, receives exactly one INVOKE
    per invocation that environment serves (request id, deadline), and a SHUTDOWN when a forced
    timeout ends it; a no-layer control proves the records come from the layer.
    """
    lam = ctx.client("lambda")

    layer_name = ctx.unique_name("sim2real-behav-layer-")
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _make_extension_layer_zip(EXTENSION_SRC)},
        CompatibleRuntimes=["python3.12"],
    )
    ctx.on_cleanup(
        lambda n=layer_name, v=published["Version"]:
        lam.delete_layer_version(LayerName=n, VersionNumber=v)
    )

    fn = ctx.unique_name("sim2real-behav-fn-")
    created = _create_function_retrying(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER_SRC)},
        MemorySize=512, Timeout=FN_TIMEOUT_S,
        Layers=[published["LayerVersionArn"]],
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    fn_arn = created["FunctionArn"]
    _wait_ready(lam, fn)
    # One slot, so the invocations below run one at a time.
    conc = lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=1)
    assert conc["ReservedConcurrentExecutions"] == 1, conc

    cold = _invoke(lam, fn, {}, tail=True)
    assert not cold["function_error"], (
        f"the extension must not break the invocation: FunctionError="
        f"{cold['function_error']!r} {cold['raw'][:400]!r}"
    )
    bodies = [cold["body"]] + [_invoke(lam, fn, {})["body"] for _ in range(2)]

    # Lambda may recycle an environment at any time, so each environment (env_id) is graded on its
    # own: its handler counts 1..n, and its extension -- the LAST registration on its /tmp, since
    # init completes before any invoke -- saw exactly that environment's invocations.
    groups: dict = {}
    for b in bodies:
        groups.setdefault(b["env_id"], []).append(b)
    envs = set(groups)
    idents: dict = {}
    by_rid: dict = {}
    for env, served in groups.items():
        assert [b["invoke_count"] for b in served] == list(range(1, len(served) + 1)), (
            f"environment {env} must count its invocations 1..n, got "
            f"{[b['invoke_count'] for b in served]!r}"
        )
        last = served[-1]
        assert last["ext_log_exists"], (
            f"the extension never wrote {'/tmp/sim2real-ext.log'!r}; nothing under "
            f"/opt/extensions/ was executed"
        )
        regs = _records(last, "register")
        assert regs, f"no registration record in environment {env}: {last['ext_records']!r}"
        reg = regs[-1]
        ident = reg["identifier"]
        # (1) it registered, and the identifier is a real UUID rather than a placeholder.
        assert ident, f"register returned no Lambda-Extension-Identifier header: {reg!r}"
        assert str(uuid.UUID(ident)) == ident, (
            f"Lambda-Extension-Identifier must be a UUID, got {ident!r}"
        )
        assert ident not in idents.values(), (
            f"two execution environments share the extension identifier {ident!r}"
        )
        idents[env] = ident

        # (2) the Extensions API told the extension the truth about its function.
        reg_body = reg["body"]
        assert reg_body.get("functionName") == fn, (
            f"register response functionName must be {fn!r}, got {reg_body.get('functionName')!r} "
            f"(full body {reg_body!r})"
        )
        assert reg_body.get("functionVersion") == "$LATEST", (
            f"register response functionVersion must be '$LATEST', got "
            f"{reg_body.get('functionVersion')!r}"
        )
        assert reg_body.get("handler") == "index.handler", (
            f"register response handler must be 'index.handler', got {reg_body.get('handler')!r}"
        )

        # (3) the extension is a separate PROCESS in the same environment, not a library call.
        assert reg["pid"] != last["handler_pid"], (
            f"the extension ran in the same process as the handler (pid "
            f"{reg['pid']!r}); an external extension is its own process"
        )

        # (5)-(7) one INVOKE event per invocation of this environment, bound to its request ids,
        # in order, all delivered to this environment's registration.
        invokes = [r for r in _records(last, "invoke") if r["identifier"] == ident]
        assert [r["event"]["requestId"] for r in invokes] == [b["request_id"] for b in served], (
            f"the extension registered as {ident!r} in environment {env} must receive exactly one "
            f"INVOKE per invocation it served, in order: got "
            f"{[r['event']['requestId'] for r in invokes]!r}, invocations "
            f"{[b['request_id'] for b in served]!r}"
        )
        by_rid.update({r["event"]["requestId"]: r for r in invokes})

    first_regs = _records(groups[bodies[0]["env_id"]][-1], "register")
    assert len(first_regs) == 1, (
        f"the function's first environment starts on an empty /tmp, so it holds exactly one "
        f"registration, got {len(first_regs)}: {first_regs!r}"
    )

    # (4) the platform discovered it by name and reported it Ready during init.
    assert "EXTENSION" in cold["log"] and f"Name: {EXT_NAME}" in cold["log"], (
        f"the cold-start log carries no EXTENSION registration line for {EXT_NAME!r}: "
        f"{cold['log'][-600:]!r}"
    )
    assert "State: Ready" in cold["log"], (
        f"the extension never reached State: Ready during init: {cold['log'][-600:]!r}"
    )

    # (8) the documented event shape, and a deadline that is computed rather than stubbed.
    for body in bodies:
        event = by_rid[body["request_id"]]["event"]
        assert event["eventType"] == "INVOKE", (
            f"eventType must be 'INVOKE', got {event.get('eventType')!r}"
        )
        assert event["invokedFunctionArn"] == fn_arn, (
            f"invokedFunctionArn must be {fn_arn!r}, got {event.get('invokedFunctionArn')!r}"
        )
        ahead_ms = event["deadlineMs"] - body["now_ms"]
        assert 0 < ahead_ms <= FN_TIMEOUT_S * 1000, (
            f"the INVOKE deadline must be within this invocation's own Timeout of "
            f"{FN_TIMEOUT_S}s and still in the future: deadlineMs={event['deadlineMs']!r} is "
            f"{ahead_ms!r}ms from the handler's own clock"
        )
        assert event["tracing"]["type"] == "X-Amzn-Trace-Id", (
            f"tracing.type must be 'X-Amzn-Trace-Id', got {event.get('tracing')!r}"
        )
        assert event["tracing"]["value"].startswith("Root=1-"), (
            f"tracing.value must be a trace header, got {event['tracing']['value']!r}"
        )

    # (9) SHUTDOWN. A forced function timeout is a documented shutdown reason, so this arm needs
    # no wait on idle spindown; the extension's SHUTDOWN record is printed into the very tail log
    # of the invocation that killed the environment.
    dying = _invoke(lam, fn, {"hang": True}, tail=True)
    assert dying["function_error"] == "Unhandled", (
        f"an invocation that outruns Timeout={FN_TIMEOUT_S}s must return FunctionError, got "
        f"{dying['function_error']!r}: {dying['raw'][:400]!r}"
    )
    timeout_payload = json.loads(dying["raw"])
    assert timeout_payload["errorType"] == "Sandbox.Timedout", (
        f"a handler timeout is reported as Sandbox.Timedout, got {timeout_payload!r}"
    )
    shutdowns = _ext_shutdown_records(dying["log"])
    assert len(shutdowns) == 1, (
        f"the dying environment must deliver exactly one SHUTDOWN event to the extension, got "
        f"{len(shutdowns)}; tail was {dying['log'][-800:]!r}"
    )
    shutdown = shutdowns[0]
    # (10) the shutdown goes to a registered extension identifier. The dying invocation may land
    # in a recycled environment, so the identifier is only required to be a UUID here and is tied
    # to that invocation's own INVOKE record below whenever the sandbox's /tmp shows it.
    dying_ident = shutdown["identifier"]
    assert dying_ident and str(uuid.UUID(dying_ident)) == dying_ident, (
        f"the SHUTDOWN went to identifier {dying_ident!r}, which is not an extension identifier"
    )
    assert shutdown["event"]["eventType"] == "SHUTDOWN", (
        f"eventType must be 'SHUTDOWN', got {shutdown['event']!r}"
    )
    assert shutdown["event"]["shutdownReason"] == "timeout", (
        f"an environment killed by a handler timeout must report shutdownReason 'timeout', got "
        f"{shutdown['event'].get('shutdownReason')!r}"
    )
    invoke_deadline = by_rid[bodies[-1]["request_id"]]["event"]["deadlineMs"]
    assert shutdown["event"]["deadlineMs"] > invoke_deadline, (
        f"the SHUTDOWN event carries its own later deadline (the extension's shutdown budget), "
        f"got {shutdown['event'].get('deadlineMs')!r} against an invoke deadline of "
        f"{invoke_deadline!r}"
    )

    # (11) the environment really died and the extension died with it: the next invocation reports
    # a new env_id on its first invocation, and the extension registers under a NEW identifier
    # that receives only this invocation.
    after = _invoke(lam, fn, {})["body"]
    assert after["env_id"] not in envs, (
        f"the timed-out execution environment was reused: {after['env_id']!r} is one of "
        f"{sorted(envs)!r}"
    )
    assert after["invoke_count"] == 1 and after["init_count"] == 1, (
        f"the replacement environment must be fresh, got invoke_count="
        f"{after['invoke_count']!r} init_count={after['init_count']!r}"
    )
    after_regs = _records(after, "register")
    assert after_regs, f"the replacement environment has no registration: {after['ext_records']!r}"
    new_ident = after_regs[-1]["identifier"]
    assert new_ident not in set(idents.values()) | {dying_ident}, (
        f"the replacement extension reused a retired identifier {new_ident!r}; the extension's "
        f"lifetime is the execution environment's"
    )
    all_invokes = _records(after, "invoke")
    # (11b) no INVOKE from before the shutdown was replayed to the new registration.
    assert [r["event"]["requestId"] for r in all_invokes if r["identifier"] == new_ident] == [
        after["request_id"]
    ], (
        f"the new registration must receive exactly its own invocation {after['request_id']!r}, "
        f"got {[r['event']['requestId'] for r in all_invokes if r['identifier'] == new_ident]!r}"
    )
    # A Sandbox.Timedout keeps the sandbox's /tmp; when this invocation reuses that sandbox, its
    # records show the timed-out invocation delivered to the registration that got the SHUTDOWN.
    dying_recs = [r for r in all_invokes if r["identifier"] == dying_ident]
    if dying_recs:
        assert dying_recs[-1]["event"]["requestId"] in timeout_payload["errorMessage"], (
            f"the last INVOKE delivered to {dying_ident!r} is "
            f"{dying_recs[-1]['event']['requestId']!r}, not the invocation the timeout error "
            f"names: {timeout_payload['errorMessage']!r}"
        )

    # (12) control: the same handler code with NO layer reports the extension log absent, so
    # every record above came from the layer rather than from the handler.
    bare = ctx.unique_name("sim2real-behav-fn-")
    _create_function_retrying(lam,
        FunctionName=bare, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER_SRC)},
        MemorySize=512, Timeout=FN_TIMEOUT_S,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, bare))
    _wait_ready(lam, bare)
    control = _invoke(lam, bare, {})["body"]
    assert control["ext_log_exists"] is False and control["ext_records"] == [], (
        f"a function with no extension layer must see no extension records, got "
        f"{control['ext_records']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
