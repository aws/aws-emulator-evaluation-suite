"""java21-unresolvable-handler-string-rejected-at-invoke-not-at-config."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "java21-unresolvable-handler-string-rejected-at-invoke-not-at-config"
GROUP = 'rejected'
SERVICES = ['lambda']

# Dependency-free bytecode: probe.H implements no interface and takes no Context, so the package
# needs nothing from Maven. The classes are embedded as base64 with their SHA-256 asserted, so the
# check needs no JDK.
JAVA_SOURCE = r'''
package probe;
public class H {                    // NOT a RequestHandler implementor -> needs "::mainHandler"
    static { Order.mark("H.<clinit>"); }
    public H() { Order.mark("H.<init>"); ctorCount++; }
    public Map<String, Object> mainHandler(In in) {
        invokeCount++;
        System.out.println("PROBE-RAN invoke=" + invokeCount);   // the effect-absent probe
        ...
    }
}
'''

_SHA256 = {
    "probe/Order.class": "02ef1b4647bdaff11aabd15f6556e07de0fdab0a024797a09fe5dd83e394edd9",
    "probe/In.class": "17d036d34668afa414fec627b2a051e1c73a4d3b1309fee8dfac24290659e56a",
    "probe/H.class": "264638719a6b69d61768bfafd7026d3bc15cd92ea46591acb639ca8b9c46f183",
}

_B64 = {  # @@GENERATED@@ probe/Order.class probe/In.class probe/H.class
    "probe/Order.class":
        "yv66vgAAAEEAKgoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCQAIAAkHAAoMAAsADAEA"
        "C3Byb2JlL09yZGVyAQADTE9HAQAQTGphdmEvdXRpbC9MaXN0OwsADgAPBwAQDAARABIBAA5qYXZhL3V0aWwvTGlzdAEAA2Fk"
        "ZAEAFShMamF2YS9sYW5nL09iamVjdDspWgsADgAUDAAVABYBAARzaXplAQADKClJBwAYAQATamF2YS91dGlsL0FycmF5TGlz"
        "dAoAFwADCAAbAQAOT3JkZXIuPGNsaW5pdD4BAAlTaWduYXR1cmUBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9TdHJp"
        "bmc7PjsBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEADUxwcm9iZS9PcmRl"
        "cjsBAARtYXJrAQAVKExqYXZhL2xhbmcvU3RyaW5nOylJAQABcwEAEkxqYXZhL2xhbmcvU3RyaW5nOwEACDxjbGluaXQ+AQAK"
        "U291cmNlRmlsZQEACk9yZGVyLmphdmEAIQAIAAIAAAABABkACwAMAAEAHAAAAAIAHQADAAEABQAGAAEAHgAAAC8AAQABAAAA"
        "BSq3AAGxAAAAAgAfAAAABgABAAAABAAgAAAADAABAAAABQAhACIAAAAJACMAJAABAB4AAAA9AAIAAQAAABOyAAcquQANAgBX"
        "sgAHuQATAQCsAAAAAgAfAAAABgABAAAABwAgAAAADAABAAAAEwAlACYAAAAIACcABgABAB4AAAAyAAIAAAAAABa7ABdZtwAZ"
        "swAHsgAHEhq5AA0CAFexAAAAAQAfAAAACgACAAAABQAKAAYAAQAoAAAAAgAp",
    "probe/In.class":
        "yv66vgAAAEEAGQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAIcHJvYmUvSW4B"
        "AARtb2RlAQASTGphdmEvbGFuZy9TdHJpbmc7AQABbgEAAUkBAAVpdGVtcwEAEExqYXZhL3V0aWwvTGlzdDsBAAlTaWduYXR1"
        "cmUBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9TdHJpbmc7PjsBAAZob2xkTXMBAARDb2RlAQAPTGluZU51bWJlclRh"
        "YmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEACkxwcm9iZS9JbjsBAApTb3VyY2VGaWxlAQAHSW4uamF2YQAhAAcA"
        "AgAAAAQAAQAJAAoAAAABAAsADAAAAAEADQAOAAEADwAAAAIAEAABABEADAAAAAEAAQAFAAYAAQASAAAALwABAAEAAAAFKrcA"
        "AbEAAAACABMAAAAGAAEAAAAEABQAAAAMAAEAAAAFABUAFgAAAAEAFwAAAAIAGA==",
    "probe/H.class":
        "yv66vgAAAEEA3goAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAISC48aW5pdD4K"
        "AAoACwcADAwADQAOAQALcHJvYmUvT3JkZXIBAARtYXJrAQAVKExqYXZhL2xhbmcvU3RyaW5nOylJCQAQABEHABIMABMAFAEA"
        "B3Byb2JlL0gBAAljdG9yQ291bnQBAAFJCQAQABYMABcAFAEAC2ludm9rZUNvdW50CQAZABoHABsMABwAHQEAEGphdmEvbGFu"
        "Zy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsSAAAAHwwAIAAhAQAXbWFrZUNvbmNhdFdpdGhDb25zdGFu"
        "dHMBABUoSSlMamF2YS9sYW5nL1N0cmluZzsKACMAJAcAJQwAJgAnAQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4B"
        "ABUoTGphdmEvbGFuZy9TdHJpbmc7KVYJACkAKgcAKwwALAAUAQAIcHJvYmUvSW4BAAZob2xkTXMKAC4ALwcAMAwAMQAyAQAQ"
        "amF2YS9sYW5nL1RocmVhZAEABXNsZWVwAQAEKEopVgcANAEAHmphdmEvbGFuZy9JbnRlcnJ1cHRlZEV4Y2VwdGlvbggANgEA"
        "BXRocm93CQApADgMADkAOgEABG1vZGUBABJMamF2YS9sYW5nL1N0cmluZzsKADwAPQcAPgwAPwBAAQAQamF2YS9sYW5nL1N0"
        "cmluZwEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgcAQgEAH2phdmEvbGFuZy9JbGxlZ2FsU3RhdGVFeGNlcHRp"
        "b24IAEQBABhwcm9iZS1kZWxpYmVyYXRlLWZhaWx1cmUKAEEARgwABQAnBwBIAQAXamF2YS91dGlsL0xpbmtlZEhhc2hNYXAK"
        "AEcAAwgASwEABW9yZGVyBwBNAQATamF2YS91dGlsL0FycmF5TGlzdAkACgBPDABQAFEBAANMT0cBABBMamF2YS91dGlsL0xp"
        "c3Q7CgBMAFMMAAUAVAEAGShMamF2YS91dGlsL0NvbGxlY3Rpb247KVYLAFYAVwcAWAwAWQBaAQANamF2YS91dGlsL01hcAEA"
        "A3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7CAATCgBdAF4H"
        "AF8MAGAAYQEAEWphdmEvbGFuZy9JbnRlZ2VyAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsIABcIAGQBAAZp"
        "bml0SWQJABAAZgwAZwA6AQAHSU5JVF9JRAgAaQEAC2phdmFWZXJzaW9uCABrAQAMamF2YS52ZXJzaW9uCgAZAG0MAG4AbwEA"
        "C2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsIAHEBAAZ2bU5hbWUIAHMBAAxq"
        "YXZhLnZtLm5hbWUIAHUBAAlsb2dTdHJlYW0IAHcBABpBV1NfTEFNQkRBX0xPR19TVFJFQU1fTkFNRQoAGQB5DAB6AG8BAAZn"
        "ZXRlbnYIADkIAH0BAAhuUGx1c09uZQkAKQB/DACAABQBAAFuCACCAQAGbkNsYXNzCgACAIQMAIUAhgEACGdldENsYXNzAQAT"
        "KClMamF2YS9sYW5nL0NsYXNzOwoAiACJBwCKDACLAIwBAA9qYXZhL2xhbmcvQ2xhc3MBAAdnZXROYW1lAQAUKClMamF2YS9s"
        "YW5nL1N0cmluZzsIAI4BAAVpdGVtcwkAKQCQDACOAFEIAJIBAAlpdGVtQ291bnQLAJQAlQcAlgwAlwCYAQAOamF2YS91dGls"
        "L0xpc3QBAARzaXplAQADKClJCgBMAAMKAIgAmwwAnACdAQARZ2V0RGVjbGFyZWRGaWVsZHMBABwoKVtMamF2YS9sYW5nL3Jl"
        "ZmxlY3QvRmllbGQ7CgCfAIkHAKABABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAsAlACiDACjAEABAANhZGQKAKUApgcApwwA"
        "qACpAQAVamF2YS91dGlsL0NvbGxlY3Rpb25zAQAEc29ydAEAEyhMamF2YS91dGlsL0xpc3Q7KVYIAKsBAApwb2pvRmllbGRz"
        "CACtAQAKSC48Y2xpbml0PgoArwCwBwCxDACyALMBAA5qYXZhL3V0aWwvVVVJRAEACnJhbmRvbVVVSUQBABIoKUxqYXZhL3V0"
        "aWwvVVVJRDsKAK8AtQwAtgCMAQAIdG9TdHJpbmcBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRh"
        "YmxlAQAEdGhpcwEACUxwcm9iZS9IOwEAC21haW5IYW5kbGVyAQAbKExwcm9iZS9JbjspTGphdmEvdXRpbC9NYXA7AQABZgEA"
        "GUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAJpbgEACkxwcm9iZS9JbjsBAA9MamF2YS91dGlsL01hcDsBAAZmaWVsZHMB"
        "ABZMb2NhbFZhcmlhYmxlVHlwZVRhYmxlAQA1TGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9P"
        "YmplY3Q7PjsBACRMamF2YS91dGlsL0xpc3Q8TGphdmEvbGFuZy9TdHJpbmc7PjsBAA1TdGFja01hcFRhYmxlBwDJAQAaW0xq"
        "YXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAlTaWduYXR1cmUBAEEoTHByb2JlL0luOylMamF2YS91dGlsL01hcDxMamF2YS9s"
        "YW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEACDxjbGluaXQ+AQAKU291cmNlRmlsZQEABkguamF2YQEAEEJvb3Rz"
        "dHJhcE1ldGhvZHMIANEBABJQUk9CRS1SQU4gaW52b2tlPQEPBgDTCgDUANUHANYMACAA1wEAJGphdmEvbGFuZy9pbnZva2Uv"
        "U3RyaW5nQ29uY2F0RmFjdG9yeQEAmChMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cDtMamF2YS9sYW5n"
        "L1N0cmluZztMamF2YS9sYW5nL2ludm9rZS9NZXRob2RUeXBlO0xqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL09iamVj"
        "dDspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7AQAMSW5uZXJDbGFzc2VzBwDaAQAlamF2YS9sYW5nL2ludm9rZS9NZXRo"
        "b2RIYW5kbGVzJExvb2t1cAcA3AEAHmphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcwEABkxvb2t1cAAhABAAAgAAAAMA"
        "GABnADoAAAAIABMAFAAAAAgAFwAUAAAAAwABAAUABgABALcAAAA9AAIAAQAAABMqtwABEge4AAlXsgAPBGCzAA+xAAAAAgC4"
        "AAAABgABAAAAEwC5AAAADAABAAAAEwC6ALsAAAABALwAvQACALcAAAN7AAUACAAAAYOyABUEYLMAFbIAGLIAFboAHgAAtgAi"
        "K8YAFiu0ACieAA8rtAAohbgALacABE0rxgAZEjUrtAA3tgA7mQANuwBBWRJDtwBFv7sAR1m3AElNLBJKuwBMWbIATrcAUrkA"
        "VQMAVywSW7IAD7gAXLkAVQMAVywSYrIAFbgAXLkAVQMAVywSY7IAZbkAVQMAVywSaBJquABsuQBVAwBXLBJwEnK4AGy5AFUD"
        "AFcsEnQSdrgAeLkAVQMAVywSeyvHAAcBpwAHK7QAN7kAVQMAVywSfCvHAAcCpwAJK7QAfgRguABcuQBVAwBXLBKBK8cABwGn"
        "ABArtAB+uABctgCDtgCHuQBVAwBXLBKNK8cABwGnAAcrtACPuQBVAwBXLBKRK8YACiu0AI/HAAcCpwAMK7QAj7kAkwEAuABc"
        "uQBVAwBXuwBMWbcAmU4SKbYAmjoEGQS+NgUDNgYVBhUFogAcGQQVBjI6By0ZB7YAnrkAoQIAV4QGAaf/4y24AKQsEqotuQBV"
        "AwBXLLAAAQAhACkALAAzAAQAuAAAAGIAGAAAABYACAAZABYAGgAhABsALQAdAD0AHgBHACAATwAhAGIAIgBxACMAgAAkAIwA"
        "JQCaACYAqAAnALYAKADLACkA5QAqAQMAKwEYACwBPAAtAUQALgFzAC8BdwAwAYEAMQC5AAAANAAFAWEADAC+AL8ABwAAAYMA"
        "ugC7AAAAAAGDAMAAwQABAE8BNAAcAMIAAgFEAD8AwwBRAAMAxAAAABYAAgBPATQAHADFAAIBRAA/AMMAxgADAMcAAAEgABBs"
        "BwAzABn/AHkAAwcAEAcAKQcAVgACBwBWBwA8/wADAAMHABAHACkHAFYAAwcAVgcAPAcAAv8AEAADBwAQBwApBwBWAAIHAFYH"
        "ADz/AAUAAwcAEAcAKQcAVgADBwBWBwA8Af8AEwADBwAQBwApBwBWAAIHAFYHADz/AAwAAwcAEAcAKQcAVgADBwBWBwA8BwAC"
        "/wAQAAMHABAHACkHAFYAAgcAVgcAPP8AAwADBwAQBwApBwBWAAMHAFYHADwHAAL/ABMAAwcAEAcAKQcAVgACBwBWBwA8/wAD"
        "AAMHABAHACkHAFYAAgcAVgcAPP8ACAADBwAQBwApBwBWAAMHAFYHADwB/wAfAAcHABAHACkHAFYHAJQHAMgBAQAA+AAfAMoA"
        "AAACAMsACADMAAYAAQC3AAAAPAABAAAAAAAYEqy4AAlXuACutgC0swBlA7MADwOzABWxAAAAAQC4AAAAEgAEAAAADQAGAA8A"
        "DwAQABMAEQADAM0AAAACAM4AzwAAAAgAAQDSAAEA0ADYAAAACgABANkA2wDdABk=",
}

GOOD = "probe.H::mainHandler"

# Three ways to make a handler string unresolvable, each breaking exactly ONE thing about the SAME
# mechanism — the runtime resolving a "<class>[::<method>]" string against the loaded classes — and
# each answered by real AWS with its own exact message.
BROKEN = [
    # (handler, errorMessage, errorType or None when the runtime emits no errorType key)
    ("probe.H",
     "Class does not implement an appropriate handler interface: probe.H",
     None),
    ("probe.Nope::x",
     "Class not found: probe.Nope",
     "java.lang.ClassNotFoundException"),
    ("probe.H::nosuch",
     "No public method named nosuch with appropriate method signature found on class probe.H",
     None),
]


# ===== helpers =====
def _deployment_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, b64 in _B64.items():
            raw = base64.b64decode(b64)
            got = hashlib.sha256(raw).hexdigest()
            assert got == _SHA256[arc], (
                f"embedded artifact {arc!r} is sha256 {got!r}, pinned {_SHA256[arc]!r} — the "
                f"bytecode under test is not the bytecode this check was verified against"
            )
            zf.writestr(arc, raw)
    return buf.getvalue()


_EXEC_ROLES = {}


def _exec_role_arn(ctx):
    """An execution role this check creates, shared by every function it deploys."""
    cached = _EXEC_ROLES.get(id(ctx))
    if cached is not None and cached[0] is ctx:
        return cached[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    _EXEC_ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, kwargs, timeout_s=90):
    """CreateFunction, retried while a freshly created role is not yet assumable by Lambda."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed by Lambda" in err.get("Message", "")
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


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
    raise AssertionError(f"log group {group} kept reappearing after its deletes")


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


def _invoke(lam, fn, payload):
    resp = lam.invoke(FunctionName=fn, LogType="Tail", Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{fn}: StatusCode {resp['StatusCode']!r} {raw!r}"
    log = base64.b64decode(resp["LogResult"]).decode("utf8", "replace")
    return resp.get("FunctionError"), json.loads(raw), log


def _set_handler(lam, fn, handler):
    """Set Handler and return the configuration read back. Never asserts on the write itself."""
    lam.update_function_configuration(FunctionName=fn, Handler=handler)
    return _wait_active(lam, fn)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """An unresolvable Java handler string is stored by UpdateFunctionConfiguration and refused at
    invoke with its exact message, no customer code running; a second invoke refuses identically,
    and restoring the working handler recovers the function."""
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-javabadhandler-")
    _create_function(lam, dict(
        FunctionName=fn, Runtime="java21", Handler=GOOD,
        Role=_exec_role_arn(ctx), Code={"ZipFile": _deployment_zip()}, MemorySize=512, Timeout=30,
        Tags={"sim2real:managed": "true"},
    ))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    _wait_active(lam, fn)

    # ---- positive control FIRST: the package and the working handler string both work -------
    err, body, log = _invoke(lam, fn, {"n": 3})
    assert err is None, f"the baseline handler {GOOD!r} failed: FunctionError={err!r} {body!r}"
    assert body["nPlusOne"] == 4, f"the baseline invocation returned {body!r}"
    assert "PROBE-RAN" in log, (
        f"the baseline invocation did not print the customer marker, so its absence below would "
        f"prove nothing: {log[:400]!r}"
    )

    for handler, want_message, want_type in BROKEN:
        # ---- break exactly one thing: the handler string ----------------------------------
        cfg = _set_handler(lam, fn, handler)

        # The control plane accepts it: handler resolution happens in the JVM at invoke time.
        assert cfg["Handler"] == handler, (
            f"UpdateFunctionConfiguration did not store the unresolvable handler string "
            f"{handler!r}; GetFunctionConfiguration reads back {cfg['Handler']!r}. Resolution "
            f"happens in the JVM at invoke time, so the control plane must accept this"
        )
        assert cfg["State"] == "Active", (
            f"the function left State=Active after storing {handler!r}: {cfg['State']!r} "
            f"{cfg.get('StateReason')!r} — an unresolvable handler is not a create/update failure"
        )

        err, body, log = _invoke(lam, fn, {"n": 3})
        assert err == "Unhandled", (
            f"invoking with the unresolvable handler {handler!r} returned "
            f"FunctionError={err!r} and payload {body!r}; real AWS refuses it as 'Unhandled'"
        )
        assert body.get("errorMessage") == want_message, (
            f"handler {handler!r} produced errorMessage {body.get('errorMessage')!r}, expected "
            f"exactly {want_message!r}"
        )
        # The runtime's own resolution refusals carry no errorType; a class-loading failure does.
        if want_type is None:
            assert "errorType" not in body, (
                f"handler {handler!r} is refused by the runtime's own resolver, which emits no "
                f"errorType key, but the payload carried errorType={body.get('errorType')!r}. "
                f"Only a genuine Java class-loading exception gets one"
            )
        else:
            assert body.get("errorType") == want_type, (
                f"handler {handler!r} produced errorType {body.get('errorType')!r}, expected "
                f"exactly {want_type!r}"
            )

        # ---- effect absent: no customer code ran ------------------------------------------
        assert "PROBE-RAN" not in log, (
            f"the customer marker appeared in the log for handler {handler!r}, so the handler body "
            f"executed despite the string being unresolvable: {log[-600:]!r}"
        )

        # ---- retry: a second invoke refuses identically ---
        err2, body2, log2 = _invoke(lam, fn, {"n": 3})
        assert err2 == "Unhandled" and body2.get("errorMessage") == want_message, (
            f"the retry of handler {handler!r} did not reproduce the refusal: "
            f"FunctionError={err2!r} payload={body2!r}"
        )
        assert "PROBE-RAN" not in log2, (
            f"the retry executed the handler body: {log2[-600:]!r}"
        )

    # ---- positive control AFTER: reverting the one broken thing restores the function -------
    cfg = _set_handler(lam, fn, GOOD)
    assert cfg["Handler"] == GOOD, f"reverting the handler did not take: {cfg['Handler']!r}"
    err, body, log = _invoke(lam, fn, {"n": 3})
    assert err is None, (
        f"the function did not recover once the handler string was corrected: FunctionError={err!r} "
        f"{body!r} — so the refusals above were not about the handler string"
    )
    assert body["nPlusOne"] == 4 and body["ctorCount"] == 1, (
        f"the recovered invocation returned {body!r}"
    )
    assert "PROBE-RAN" in log, f"the recovered invocation ran no customer code: {log[:400]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
