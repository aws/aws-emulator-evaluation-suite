"""java-package-root-classes-and-lib-jars-resolve-alphabetically."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-package-root-classes-and-lib-jars-resolve-alphabetically"
GROUP = "java-packaging"
SERVICES = ["lambda"]

# The bytecode is embedded as base64 with its SHA-256 asserted, so the check needs no JDK. Built
# with `javac` under Amazon Corretto 8, so the same class files run on every supported Java
# identifier. Sources, for reference:
#
#   package probe;
#   public class RootHandlerA {
#       public Map<String, Object> handle(Map<String, Object> in) {
#           Map<String, Object> out = new HashMap<>();
#           out.put("dupMarker", probe.lib.Dup.marker());
#           out.put("rootRan", true);
#           return out;
#       }
#   }
#
#   package probe.lib;
#   public class Dup { public static String marker() { return "aaa"; } }  // and "zzz", a second build
_SHA256 = {
    "RootHandlerA": "fe41f30ab192e7df03869bab83e79077f59887fd11b8065d429e753bac17757f",
    "Dup_aaa": "c3a5c426446239e21fccdb46a4742ef8df3a0a60d10999b60599dd2bb72d2ef5",
    "Dup_zzz": "06c97a324a5a759622a9470fad6ca6d67b345717bd4ba73b517d13b774fdc016",
}

_B64 = {  # @@GENERATED@@ RootHandlerA Dup_aaa Dup_zzz
    "RootHandlerA":
        "yv66vgAAADQAKgoACgAVBwAWCgACABUIABcKABgAGQsAGgAbCAAcCgAdAB4HAB8HACABAAY8aW5pdD4BAAMoKVYBAARDb2Rl"
        "AQAPTGluZU51bWJlclRhYmxlAQAGaGFuZGxlAQAgKExqYXZhL3V0aWwvTWFwOylMamF2YS91dGlsL01hcDsBAAlTaWduYXR1"
        "cmUBAGwoTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7PjspTGphdmEvdXRpbC9N"
        "YXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7PjsBAApTb3VyY2VGaWxlAQARUm9vdEhhbmRsZXJBLmph"
        "dmEMAAsADAEAEWphdmEvdXRpbC9IYXNoTWFwAQAJZHVwTWFya2VyBwAhDAAiACMHACQMACUAJgEAB3Jvb3RSYW4HACcMACgA"
        "KQEAEnByb2JlL1Jvb3RIYW5kbGVyQQEAEGphdmEvbGFuZy9PYmplY3QBAA1wcm9iZS9saWIvRHVwAQAGbWFya2VyAQAUKClM"
        "amF2YS9sYW5nL1N0cmluZzsBAA1qYXZhL3V0aWwvTWFwAQADcHV0AQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcv"
        "T2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBABFqYXZhL2xhbmcvQm9vbGVhbgEAB3ZhbHVlT2YBABYoWilMamF2YS9sYW5n"
        "L0Jvb2xlYW47ACEACQAKAAAAAAACAAEACwAMAAEADQAAAB0AAQABAAAABSq3AAGxAAAAAQAOAAAABgABAAAABwABAA8AEAAC"
        "AA0AAABHAAMAAwAAACO7AAJZtwADTSwSBLgABbkABgMAVywSBwS4AAi5AAYDAFcssAAAAAEADgAAABIABAAAAAkACAAKABQA"
        "CwAhAAwAEQAAAAIAEgABABMAAAACABQ=",
    "Dup_aaa":
        "yv66vgAAADQAEQoABAANCAAOBwAPBwAQAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEABm1hcmtl"
        "cgEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEACER1cC5qYXZhDAAFAAYBAANhYWEBAA1wcm9iZS9saWIv"
        "RHVwAQAQamF2YS9sYW5nL09iamVjdAAhAAMABAAAAAAAAgABAAUABgABAAcAAAAdAAEAAQAAAAUqtwABsQAAAAEACAAAAAYA"
        "AQAAAAMACQAJAAoAAQAHAAAAGwABAAAAAAADEgKwAAAAAQAIAAAABgABAAAABQABAAsAAAACAAw=",
    "Dup_zzz":
        "yv66vgAAADQAEQoABAANCAAOBwAPBwAQAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEABm1hcmtl"
        "cgEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEACER1cC5qYXZhDAAFAAYBAAN6enoBAA1wcm9iZS9saWIv"
        "RHVwAQAQamF2YS9sYW5nL09iamVjdAAhAAMABAAAAAAAAgABAAUABgABAAcAAAAdAAEAAQAAAAUqtwABsQAAAAEACAAAAAYA"
        "AQAAAAMACQAJAAoAAQAHAAAAGwABAAAAAAADEgKwAAAAAQAIAAAABgABAAAABQABAAsAAAACAAw=",
}


def _class_bytes(key: str) -> bytes:
    raw = base64.b64decode(_B64[key])
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256[key], (
        f"embedded class {key!r} is sha256 {got!r}, pinned {_SHA256[key]!r} — the bytecode under "
        f"test is not the bytecode this check was verified against"
    )
    return raw


def _jar(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, raw in entries.items():
            zf.writestr(arc, raw)
    return buf.getvalue()


def _package_zip(with_lib: bool) -> bytes:
    """The root handler class at the zip root, plus two lib/*.jar each shadowing probe.lib.Dup."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("probe/RootHandlerA.class", _class_bytes("RootHandlerA"))
        if with_lib:
            # Written zzz before aaa: an implementation that loads jars in archive/insertion
            # order rather than sorting by name would pick zzz, so the two orders disagree.
            zf.writestr("lib/zzz-dup.jar", _jar({"probe/lib/Dup.class": _class_bytes("Dup_zzz")}))
            zf.writestr("lib/aaa-dup.jar", _jar({"probe/lib/Dup.class": _class_bytes("Dup_aaa")}))
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A root-level class resolves on the classpath alongside dependency jars under lib/, and when
    two lib/*.jar files declare the same class, the one earlier in Unicode alphabetical order wins.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-package.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-javapkg-")
    _function(ctx, FunctionName=fn, Runtime="java21", Handler="probe.RootHandlerA::handle",
              Role=_execution_role(ctx), MemorySize=512, Timeout=20,
              Code={"ZipFile": _package_zip(with_lib=True)})

    r = _invoke(lam, fn, b"{}")
    assert r["error"] is None, f"root+lib invoke failed: {r['error']!r} {r['raw'][:400]!r}"
    body = json.loads(r["raw"])
    assert body["rootRan"] is True, (
        f"the root-level class probe.RootHandlerA did not run: {body!r}"
    )
    assert body["dupMarker"] == "aaa", (
        f"two lib/*.jar files each declare probe.lib.Dup; AWS loads JAR files in Unicode "
        f"alphabetical order and uses the first one's class, so 'lib/aaa-dup.jar' (MARKER='aaa') "
        f"must win over 'lib/zzz-dup.jar' (MARKER='zzz'), but the handler reported {body!r}"
    )

    # Negative control: the SAME root class, with lib/ removed. probe.lib.Dup is now unresolvable,
    # so the dependency jars were load-bearing rather than coincidental. A still-warm environment
    # from the invoke above may serve one more invoke on the old code, so this polls to the
    # terminal state rather than asserting on the first reply.
    lam.update_function_code(FunctionName=fn, ZipFile=_package_zip(with_lib=False))
    _wait_active(lam, fn)
    r2 = _poll(lambda: _invoke(lam, fn, b"{}"), lambda r: r["error"] is not None,
               timeout_s=90, interval_s=3, what="the updated code (no lib/) takes effect")
    assert r2["error"] == "Unhandled", (
        f"removing lib/*.jar left probe.lib.Dup unresolvable; expected the invoke to fail, but it "
        f"returned FunctionError={r2['error']!r} body={r2['raw'][:400]!r}"
    )
    body2 = json.loads(r2["raw"])
    assert body2.get("errorType") == "java.lang.NoClassDefFoundError", (
        f"without lib/, resolving probe.lib.Dup must fail as NoClassDefFoundError, got {body2!r}"
    )
    assert body2.get("errorMessage") == "probe/lib/Dup", (
        f"errorMessage was {body2.get('errorMessage')!r}, expected the JVM's own internal-form "
        f"class name 'probe/lib/Dup'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
