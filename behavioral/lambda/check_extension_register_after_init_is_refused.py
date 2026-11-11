"""extension-register-after-init-is-refused."""

from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extension-register-after-init-is-refused"
GROUP = "extensions_runtime"
SERVICES = ["lambda"]

EXT_FILE_NAME = "latereg"

# Registers once during Init (as the Extensions API requires), then calls /register a second
# time from inside the INVOKE phase and records that second call's own status and body, before
# resuming normal INVOKE/SHUTDOWN handling so the function keeps working either way.
_EXTENSION = """\
#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ["AWS_LAMBDA_RUNTIME_API"]
LOG = "/tmp/sim2real-ext.log"
NAME = os.path.basename(__file__)


def _append(rec):
    with open(LOG, "a") as fh:
        fh.write(json.dumps(rec) + "\\n")
        fh.flush()


def _register():
    req = urllib.request.Request(
        "http://%s/2020-01-01/extension/register" % API,
        data=json.dumps({"events": ["INVOKE", "SHUTDOWN"]}).encode(),
        headers={"Lambda-Extension-Name": NAME, "Content-Type": "application/json"},
        method="POST")
    with urllib.request.urlopen(req) as r:
        return r.status, r.headers.get("Lambda-Extension-Identifier"), json.loads(r.read())


status, ident, _ = _register()
_append({"kind": "register", "identifier": ident, "status": status})

while True:
    nxt = urllib.request.Request(
        "http://%s/2020-01-01/extension/event/next" % API,
        headers={"Lambda-Extension-Identifier": ident})
    with urllib.request.urlopen(nxt) as r:
        ev = json.loads(r.read())
    if ev.get("eventType") == "SHUTDOWN":
        _append({"kind": "EXT_SHUTDOWN", "event": ev})
        sys.exit(0)
    # Already past Init: a second Register call for the same extension process.
    try:
        late_status, late_ident, late_body = _register()
        _append({"kind": "late_register", "status": late_status, "identifier": late_ident,
                  "body": late_body, "request_id": ev.get("requestId")})
    except urllib.error.HTTPError as e:
        _append({"kind": "late_register_error", "status": e.code,
                  "body": e.read().decode("utf-8", "replace"), "request_id": ev.get("requestId")})
"""

_HANDLER = """\
import json
import os
import time


def handler(event, context):
    deadline = time.time() + 5.0
    recs = []
    while True:
        recs = []
        if os.path.exists("/tmp/sim2real-ext.log"):
            with open("/tmp/sim2real-ext.log") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        recs.append(json.loads(line))
        if any(r.get("kind", "").startswith("late_register")
               and r.get("request_id") == context.aws_request_id for r in recs):
            break
        if time.time() >= deadline:
            break
        time.sleep(0.1)
    return {"records": recs, "request_id": context.aws_request_id}
"""


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Register call made after the extension has completed Init and is handling INVOKE fails;
    the extension's own INVOKE handling is unaffected by the refusal, proven by a later invocation
    whose own late Register attempt still reaches the extension.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-extensions-api.html
    """
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-latereg-")
    layer = lam.publish_layer_version(
        LayerName=layer_name, Description="sim2real late-register extension",
        Content={"ZipFile": _zip({f"extensions/{EXT_FILE_NAME}": (_EXTENSION, 0o755)})},
        CompatibleRuntimes=["python3.12"])
    ctx.on_cleanup(_teardown(lambda: lam.delete_layer_version(
        LayerName=layer_name, VersionNumber=layer["Version"]), "ResourceNotFoundException"))

    fn = ctx.unique_name("sim2real-behav-latereg-")
    _function(ctx, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
              Role=_execution_role(ctx), MemorySize=256, Timeout=15,
              Code={"ZipFile": _zip({"index.py": (_HANDLER, 0o644)})},
              Layers=[layer["LayerVersionArn"]])

    first = _invoke(lam, fn, b"{}")
    assert first["error"] is None, (
        f"an invocation while a late register is attempted must still succeed: "
        f"error={first['error']!r} raw={first['raw'][:400]!r}")
    body = json.loads(first["raw"])
    records = body["records"]
    late = [r for r in records if r["kind"].startswith("late_register")
            and r.get("request_id") == body["request_id"]]
    assert late, f"no late-register attempt recorded for this invocation: {records!r}"
    late = late[0]
    assert late["kind"] == "late_register_error" and late["status"] == 403, (
        f"a Register call made after Init completes must be refused with HTTP 403, got "
        f"{late!r}")
    err = json.loads(late["body"])
    assert err["errorType"] == "Extension.InvalidExtensionState", (
        f"errorType must be 'Extension.InvalidExtensionState', got {err!r}")
    assert err["errorMessage"] == (
        f"State transition from Running to Registered failed for extension "
        f"{EXT_FILE_NAME}. Error: State transition is not allowed"
    ), f"errorMessage {err['errorMessage']!r}"

    registers = [r for r in records if r["kind"] == "register"]
    assert registers and registers[0]["status"] == 200, (
        f"the extension's own Init-phase registration must have succeeded: {registers!r}")

    second = _invoke(lam, fn, b"{}")
    assert second["error"] is None, (
        f"a later invocation must still succeed after a refused late register: "
        f"error={second['error']!r} raw={second['raw'][:400]!r}")
    second_body = json.loads(second["raw"])
    second_late = [r for r in second_body["records"] if r["kind"].startswith("late_register")
                   and r.get("request_id") == second_body["request_id"]]
    assert second_late, (
        f"no late-register attempt recorded for the later invocation either, so INVOKE delivery "
        f"to the extension cannot be shown unaffected by the earlier refusal: "
        f"{second_body['records']!r}")


def _zip(files: dict) -> bytes:
    """A zip of ``{arcname: (text, mode)}``; the mode lands in the entry's Unix permission bits."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, (text, mode) in files.items():
            info = zipfile.ZipInfo(arc, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, textwrap.dedent(text))
    return buf.getvalue()




def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _execution_role(ctx, statements=None) -> str:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so no function
    of this check ever creates a log group that could outlive it (LogType=Tail needs none)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return arn


def _function(ctx, **kwargs) -> dict:
    """CreateFunction through the role-propagation window, its delete registered, then Active."""
    lam = ctx.client("lambda")
    kwargs.setdefault("Tags", {"sim2real": CHECK})

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    name = kwargs["FunctionName"]
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    _wait_active(lam, name)
    return out


def _wait_active(lam, name, qualifier=None) -> dict:
    args = {"FunctionName": name}
    if qualifier:
        args["Qualifier"] = qualifier
    conf = _poll(lambda: lam.get_function_configuration(**args),
                 lambda c: c.get("State", "Active") in ("Active", "Failed")
                 and c.get("LastUpdateStatus", "Successful") != "InProgress",
                 timeout_s=300, interval_s=2, what=f"function {name} settles")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return conf


def _invoke(lam, name, payload: bytes, qualifier=None) -> dict:
    """One RequestResponse invoke with the log tail: status, error flag, raw payload, request id."""
    args = {"FunctionName": name, "InvocationType": "RequestResponse", "LogType": "Tail",
            "Payload": payload}
    if qualifier:
        args["Qualifier"] = qualifier
    resp = lam.invoke(**args)
    return {"status": resp["StatusCode"], "error": resp.get("FunctionError"),
            "raw": resp["Payload"].read(),
            "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
            "request_id": resp["ResponseMetadata"]["RequestId"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
