"""external-extension-that-exits-before-registering-fails-the-invoke."""
from __future__ import annotations

import base64
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "external-extension-that-exits-before-registering-fails-the-invoke"
GROUP = "extensions_runtime"
SERVICES = ["lambda"]

# Discovered by Lambda as an external extension because it is an executable under extensions/ in
# a layer (mounted at /opt/extensions/). It never calls /extension/register.
_EXTENSION = """\
#!/bin/sh
echo "PROBE-EXT-STARTED"
exit 3
"""

_HANDLER = """\
def handler(event, context):
    print("PROBE-HANDLER-RAN")
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A layer extension that exits before registering with the Extensions API fails every invoke with
    Extension.Crash "exit status 3" without running the handler; removing the layer from the same
    function lets the next invoke succeed.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-extensions-api.html
    """
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-extlayer-")
    layer = lam.publish_layer_version(
        LayerName=layer_name, Description="sim2real crashing extension",
        Content={"ZipFile": _zip({"extensions/crasher": (_EXTENSION, 0o755)})},
        CompatibleRuntimes=["python3.12"])
    ctx.on_cleanup(_teardown(lambda: lam.delete_layer_version(
        LayerName=layer_name, VersionNumber=layer["Version"]), "ResourceNotFoundException"))

    fn = ctx.unique_name("sim2real-behav-extcrash-")
    _function(ctx, FunctionName=fn, Runtime="python3.12", Handler="index.handler",
              Role=_execution_role(ctx), MemorySize=256, Timeout=15,
              Code={"ZipFile": _zip({"index.py": (_HANDLER, 0o644)})},
              Layers=[layer["LayerVersionArn"]])

    bad = _invoke(lam, fn, b"{}")
    assert bad["status"] == 200 and bad["error"] == "Unhandled", (
        f"crashing extension: status={bad['status']!r} FunctionError={bad['error']!r} "
        f"raw={bad['raw'][:400]!r}")
    doc = json.loads(bad["raw"])
    assert (doc.get("errorType"), doc.get("errorMessage")) == (
        "Extension.Crash", "RequestId: " + bad["request_id"] + " Error: exit status 3"), (
        f"error document {doc!r}")
    assert "PROBE-HANDLER-RAN" not in bad["log"], f"the handler ran: {bad['log'][-400:]!r}"

    lam.update_function_configuration(FunctionName=fn, Layers=[])
    conf = _wait_active(lam, fn)
    assert not conf.get("Layers"), f"layers still attached: {conf.get('Layers')!r}"
    ok = _invoke(lam, fn, b"{}")
    assert ok["error"] is None and json.loads(ok["raw"]) == {"ok": True}, (
        f"without the layer: error={ok['error']!r} raw={ok['raw'][:300]!r}")
    assert "PROBE-HANDLER-RAN" in ok["log"], f"handler log line missing: {ok['log'][-400:]!r}"


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
