"""java-layer-java-lib-jar-resolves-until-the-layer-is-detached."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-layer-java-lib-jar-resolves-until-the-layer-is-detached"
GROUP = "java-packaging"
SERVICES = ["lambda"]

# Built with `javac` under Amazon Corretto 8 (bytecode major version 52), so the same class files
# run on every supported Java identifier. Sources, for reference:
#
#   package probe;
#   public class RootHandlerB {
#       public Map<String, Object> handle(Map<String, Object> in) {
#           Map<String, Object> out = new HashMap<>();
#           out.put("dupMarker", probe.lib.Dup2.marker());
#           if (Boolean.TRUE.equals(in.get("wantOnlyInLayer"))) {
#               try { out.put("onlyInLayerValue", probe.lib.OnlyInLayer.value()); }
#               catch (Throwable t) { out.put("onlyInLayerError", t.getClass().getName()); }
#           }
#           return out;
#       }
#   }
#
#   package probe.lib;
#   public class Dup2 { public static String marker() { return "package"; } }   // and "layer"
#   public class OnlyInLayer { public static String value() { return "layer-only-value"; } }
_SHA256 = {
    "RootHandlerB": "dafa7816f8f59a14cc65699f060ec2210b51281d797d377b1927e5eed0c3b6e3",
    "Dup2_package": "082b2cb4975ccf1321244987331b009995dde0e327dfdafee8043747c674eff9",
    "Dup2_layer": "9f980ac4b152a6a3691ee54fb1a0946a118bdef3fc7493c79bfeb3dd9c72822d",
    "OnlyInLayer": "4efc0e74b57546c415ea84f22115e5a56c67fd2fc200bc0ff95b240c184786cc",
}

_B64 = {  # @@GENERATED@@ RootHandlerB Dup2_package Dup2_layer OnlyInLayer
    "RootHandlerB":
        "yv66vgAAADQASgoAEgAhBwAiCgACACEIACMKACQAJQsAJgAnCQAoACkIACoLACYAKwoAKAAsCAAtCgAuAC8HADAIADEKABIA"
        "MgoAMwA0BwA1BwA2AQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEABmhhbmRsZQEAIChMamF2YS91"
        "dGlsL01hcDspTGphdmEvdXRpbC9NYXA7AQANU3RhY2tNYXBUYWJsZQcANQcANwcAMAEACVNpZ25hdHVyZQEAbChMamF2YS91"
        "dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OylMamF2YS91dGlsL01hcDxMamF2YS9sYW5n"
        "L1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEAClNvdXJjZUZpbGUBABFSb290SGFuZGxlckIuamF2YQwAEwAUAQARamF2"
        "YS91dGlsL0hhc2hNYXABAAlkdXBNYXJrZXIHADgMADkAOgcANwwAOwA8BwA9DAA+AD8BAA93YW50T25seUluTGF5ZXIMAEAA"
        "QQwAQgBDAQAQb25seUluTGF5ZXJWYWx1ZQcARAwARQA6AQATamF2YS9sYW5nL1Rocm93YWJsZQEAEG9ubHlJbkxheWVyRXJy"
        "b3IMAEYARwcASAwASQA6AQAScHJvYmUvUm9vdEhhbmRsZXJCAQAQamF2YS9sYW5nL09iamVjdAEADWphdmEvdXRpbC9NYXAB"
        "AA5wcm9iZS9saWIvRHVwMgEABm1hcmtlcgEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQADcHV0AQA4KExqYXZhL2xhbmcvT2Jq"
        "ZWN0O0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBABFqYXZhL2xhbmcvQm9vbGVhbgEABFRSVUUBABNM"
        "amF2YS9sYW5nL0Jvb2xlYW47AQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAZlcXVh"
        "bHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoBABVwcm9iZS9saWIvT25seUluTGF5ZXIBAAV2YWx1ZQEACGdldENsYXNzAQAT"
        "KClMamF2YS9sYW5nL0NsYXNzOwEAD2phdmEvbGFuZy9DbGFzcwEAB2dldE5hbWUAIQARABIAAAAAAAIAAQATABQAAQAVAAAA"
        "HQABAAEAAAAFKrcAAbEAAAABABYAAAAGAAEAAAAIAAEAFwAYAAIAFQAAAJ8AAwAEAAAAR7sAAlm3AANNLBIEuAAFuQAGAwBX"
        "sgAHKxIIuQAJAgC2AAqZACMsEgu4AAy5AAYDAFenABROLBIOLbYAD7YAELkABgMAVyywAAEAJQAxADQADQACABYAAAAiAAgA"
        "AAAKAAgACwAUAAwAJQAOADEAEQA0AA8ANQAQAEUAEwAZAAAAFgAC/wA0AAMHABoHABsHABsAAQcAHBAAHQAAAAIAHgABAB8A"
        "AAACACA=",
    "Dup2_package":
        "yv66vgAAADQAEQoABAANCAAOBwAPBwAQAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEABm1hcmtl"
        "cgEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEACUR1cDIuamF2YQwABQAGAQAHcGFja2FnZQEADnByb2Jl"
        "L2xpYi9EdXAyAQAQamF2YS9sYW5nL09iamVjdAAhAAMABAAAAAAAAgABAAUABgABAAcAAAAdAAEAAQAAAAUqtwABsQAAAAEA"
        "CAAAAAYAAQAAAAMACQAJAAoAAQAHAAAAGwABAAAAAAADEgKwAAAAAQAIAAAABgABAAAABQABAAsAAAACAAw=",
    "Dup2_layer":
        "yv66vgAAADQAEQoABAANCAAOBwAPBwAQAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEABm1hcmtl"
        "cgEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEACUR1cDIuamF2YQwABQAGAQAFbGF5ZXIBAA5wcm9iZS9s"
        "aWIvRHVwMgEAEGphdmEvbGFuZy9PYmplY3QAIQADAAQAAAAAAAIAAQAFAAYAAQAHAAAAHQABAAEAAAAFKrcAAbEAAAABAAgA"
        "AAAGAAEAAAADAAkACQAKAAEABwAAABsAAQAAAAAAAxICsAAAAAEACAAAAAYAAQAAAAUAAQALAAAAAgAM",
    "OnlyInLayer":
        "yv66vgAAADQAEQoABAANCAAOBwAPBwAQAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEABXZhbHVl"
        "AQAUKClMamF2YS9sYW5nL1N0cmluZzsBAApTb3VyY2VGaWxlAQAQT25seUluTGF5ZXIuamF2YQwABQAGAQAQbGF5ZXItb25s"
        "eS12YWx1ZQEAFXByb2JlL2xpYi9Pbmx5SW5MYXllcgEAEGphdmEvbGFuZy9PYmplY3QAIQADAAQAAAAAAAIAAQAFAAYAAQAH"
        "AAAAHQABAAEAAAAFKrcAAbEAAAABAAgAAAAGAAEAAAADAAkACQAKAAEABwAAABsAAQAAAAAAAxICsAAAAAEACAAAAAYAAQAA"
        "AAUAAQALAAAAAgAM",
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


def _package_zip() -> bytes:
    """The root handler plus lib/pkgdup.jar, which provides the PACKAGE's probe.lib.Dup2."""
    return _zip({
        "probe/RootHandlerB.class": _class_bytes("RootHandlerB"),
        "lib/pkgdup.jar": _zip({"probe/lib/Dup2.class": _class_bytes("Dup2_package")}),
    })


def _layer_zip() -> bytes:
    """java/lib/layerdep.jar: the LAYER's own probe.lib.Dup2, plus a class absent from the
    package entirely, so its resolution can only come from the layer's classpath entry."""
    return _zip({
        "java/lib/layerdep.jar": _zip({
            "probe/lib/Dup2.class": _class_bytes("Dup2_layer"),
            "probe/lib/OnlyInLayer.class": _class_bytes("OnlyInLayer"),
        }),
    })




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


def _layer(ctx) -> str:
    """A published layer version holding java/lib/layerdep.jar; its delete is registered."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-javalayer-")
    resp = lam.publish_layer_version(LayerName=name, Content={"ZipFile": _layer_zip()})
    version = resp["Version"]
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_layer_version(LayerName=name, VersionNumber=version),
        "ResourceNotFoundException"))
    return resp["LayerVersionArn"]


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
    """A layer's java/lib/*.jar reaches the function's classpath, so a class present only there
    resolves; detaching the layer loses only that class, while a class the package's own lib/*.jar
    also provides resolves from the package.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-layers.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/packaging-layers.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-javalayer-")
    layer_arn = _layer(ctx)
    _function(ctx, FunctionName=fn, Runtime="java21", Handler="probe.RootHandlerB::handle",
              Role=_execution_role(ctx), MemorySize=512, Timeout=20,
              Code={"ZipFile": _package_zip()}, Layers=[layer_arn])

    r = _invoke(lam, fn, json.dumps({"wantOnlyInLayer": True}).encode())
    assert r["error"] is None, f"layer-attached invoke failed: {r['error']!r} {r['raw'][:400]!r}"
    body = json.loads(r["raw"])
    assert body.get("onlyInLayerValue") == "layer-only-value", (
        f"probe.lib.OnlyInLayer exists only in the layer's java/lib/layerdep.jar; it must resolve "
        f"once the layer is attached, got {body!r}"
    )
    # Which of two copies of one class wins is not documented, so only resolution is asserted.
    assert body.get("dupMarker") in ("package", "layer"), (
        f"probe.lib.Dup2 is declared both by the function's own lib/pkgdup.jar (marker='package') "
        f"and by the layer's java/lib/layerdep.jar (marker='layer'); one copy must resolve, but the "
        f"handler reported {body!r}"
    )

    # Negative control: detach the layer. The package's own Dup2 still resolves (the layer never
    # served it); OnlyInLayer, which the layer alone provided, is unresolvable.
    lam.update_function_configuration(FunctionName=fn, Layers=[])
    _wait_active(lam, fn)
    r2 = _poll(lambda: _invoke(lam, fn, json.dumps({"wantOnlyInLayer": True}).encode()),
               lambda r: json.loads(r["raw"]).get("onlyInLayerValue") is None,
               timeout_s=90, interval_s=3, what="the layer detach takes effect")
    assert r2["error"] is None, f"layer-detached invoke failed: {r2['error']!r} {r2['raw'][:400]!r}"
    body2 = json.loads(r2["raw"])
    assert body2.get("dupMarker") == "package", (
        f"after detaching the layer, the function's own lib/pkgdup.jar must still resolve "
        f"probe.lib.Dup2 as 'package', got {body2!r}"
    )
    assert body2.get("onlyInLayerError") == "java.lang.NoClassDefFoundError", (
        f"after detaching the layer, probe.lib.OnlyInLayer (which only the layer ever provided) "
        f"must fail to resolve as NoClassDefFoundError, got {body2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
