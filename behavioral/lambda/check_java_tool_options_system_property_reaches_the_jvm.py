"""java-tool-options-system-property-reaches-the-jvm."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-tool-options-system-property-reaches-the-jvm"
GROUP = "java-packaging"
SERVICES = ["lambda"]

_PROBE_VALUE = "lambda-tool-opts-probe"

# Built with `javac` under Amazon Corretto 8 (bytecode major version 52), so the same class file
# runs on every supported Java identifier. Source, for reference:
#
#   package probe;
#   public class ToolOptsHandler {
#       public Map<String, Object> handle(Map<String, Object> in) {
#           Map<String, Object> out = new HashMap<>();
#           out.put("marker", System.getProperty("probe.marker"));
#           out.put("toolOptsEnv", System.getenv("JAVA_TOOL_OPTIONS"));
#           return out;
#       }
#   }
_SHA256 = {
    "ToolOptsHandler": "ce7707a21b23a3a587a1efd1d80e4e9bd6c6d0483bf2c81c5b639dd733f7a0b0",
}

_B64 = {  # @@GENERATED@@ ToolOptsHandler
    "ToolOptsHandler":
        "yv66vgAAADQAKwoADAAXBwAYCgACABcIABkIABoKABsAHAsAHQAeCAAfCAAgCgAbACEHACIHACMBAAY8aW5pdD4BAAMoKVYB"
        "AARDb2RlAQAPTGluZU51bWJlclRhYmxlAQAGaGFuZGxlAQAgKExqYXZhL3V0aWwvTWFwOylMamF2YS91dGlsL01hcDsBAAlT"
        "aWduYXR1cmUBAGwoTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7PjspTGphdmEv"
        "dXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7PjsBAApTb3VyY2VGaWxlAQAUVG9vbE9wdHNI"
        "YW5kbGVyLmphdmEMAA0ADgEAEWphdmEvdXRpbC9IYXNoTWFwAQAGbWFya2VyAQAMcHJvYmUubWFya2VyBwAkDAAlACYHACcM"
        "ACgAKQEAC3Rvb2xPcHRzRW52AQARSkFWQV9UT09MX09QVElPTlMMACoAJgEAFXByb2JlL1Rvb2xPcHRzSGFuZGxlcgEAEGph"
        "dmEvbGFuZy9PYmplY3QBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxq"
        "YXZhL2xhbmcvU3RyaW5nOwEADWphdmEvdXRpbC9NYXABAANwdXQBADgoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9P"
        "YmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEABmdldGVudgAhAAsADAAAAAAAAgABAA0ADgABAA8AAAAdAAEAAQAAAAUqtwAB"
        "sQAAAAEAEAAAAAYAAQAAAAYAAQARABIAAgAPAAAASgADAAMAAAAmuwACWbcAA00sEgQSBbgABrkABwMAVywSCBIJuAAKuQAH"
        "AwBXLLAAAAABABAAAAASAAQAAAAIAAgACQAWAAoAJAALABMAAAACABQAAQAVAAAAAgAW",
}


def _class_bytes(key: str) -> bytes:
    raw = base64.b64decode(_B64[key])
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256[key], (
        f"embedded class {key!r} is sha256 {got!r}, pinned {_SHA256[key]!r} — the bytecode under "
        f"test is not the bytecode this check was verified against"
    )
    return raw


def _zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, raw in entries.items():
            zf.writestr(arc, raw)
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
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _execution_role(ctx) -> str:
    """A bare Lambda execution role with no CloudWatch Logs grant: the function never creates a
    log group, so there is nothing for this check to leak or reap."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
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
    args = {"FunctionName": name, "InvocationType": "RequestResponse", "LogType": "Tail",
            "Payload": payload}
    if qualifier:
        args["Qualifier"] = qualifier
    resp = lam.invoke(**args)
    return {"status": resp["StatusCode"], "error": resp.get("FunctionError"),
            "raw": resp["Payload"].read(),
            "log": base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace"),
            "request_id": resp["ResponseMetadata"]["RequestId"]}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """JAVA_TOOL_OPTIONS reaches the JVM: a -D flag set through it is readable from the handler
    as a system property, and removing the variable removes the property on the next invoke.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-customization.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-javatoolopts-")
    tool_opts = f"-Dprobe.marker={_PROBE_VALUE}"
    _function(ctx, FunctionName=fn, Runtime="java21", Handler="probe.ToolOptsHandler::handle",
              Role=_execution_role(ctx), MemorySize=512, Timeout=20,
              Code={"ZipFile": _zip({"probe/ToolOptsHandler.class": _class_bytes("ToolOptsHandler")})},
              Environment={"Variables": {"JAVA_TOOL_OPTIONS": tool_opts}})

    r = _invoke(lam, fn, b"{}")
    assert r["status"] == 200, f"invoke with JAVA_TOOL_OPTIONS set: StatusCode {r['status']!r}"
    assert r["error"] is None, f"invoke with JAVA_TOOL_OPTIONS set failed: {r['error']!r}"
    body = json.loads(r["raw"])
    assert body.get("toolOptsEnv") == tool_opts, (
        f"the function's own environment did not carry JAVA_TOOL_OPTIONS={tool_opts!r}: {body!r}"
    )
    assert body.get("marker") == _PROBE_VALUE, (
        f"the JVM must parse the -D flag in JAVA_TOOL_OPTIONS and expose it as a system property; "
        f"System.getProperty('probe.marker') returned {body.get('marker')!r}, expected "
        f"{_PROBE_VALUE!r}"
    )

    # Negative control: without the env var, the JVM never saw the -D flag at all. The config
    # update is already effective once LastUpdateStatus=Successful, so one invoke suffices.
    lam.update_function_configuration(FunctionName=fn, Environment={"Variables": {}})
    _wait_active(lam, fn)
    r2 = _invoke(lam, fn, b"{}")
    assert r2["status"] == 200, f"invoke without JAVA_TOOL_OPTIONS: StatusCode {r2['status']!r}"
    assert r2["error"] is None, f"invoke without JAVA_TOOL_OPTIONS failed: {r2['error']!r}"
    body2 = json.loads(r2["raw"])
    assert body2.get("toolOptsEnv") is None, (
        f"with JAVA_TOOL_OPTIONS removed, the function's own environment must not carry it, "
        f"got {body2!r}"
    )
    assert body2.get("marker") is None, (
        f"with JAVA_TOOL_OPTIONS removed, the property must be absent, got {body2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
