"""java-heap-exhaustion-reports-outofmemoryerror-with-a-java-stack-trace."""
from __future__ import annotations

import re
import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-heap-exhaustion-reports-outofmemoryerror-with-a-java-stack-trace"
GROUP = "java-packaging"
SERVICES = ["lambda"]

#: The runtime bounds the JVM heap below MemorySize; the check reads that bound from the JVM and
#: asserts it, then retains 1 MiB blocks past it, so the heap refuses the allocation before the
#: container's memory limit is reached.
_SMALL_MB = 8
_MEMORY_SIZE_MB = 1024

#: probe.HeapHandler.handle's own frame, with a line number from the bytecode's LineNumberTable.
_FRAME = re.compile(r"^probe\.HeapHandler\.handle\(HeapHandler\.java:[0-9]+\)$")

# Built with `javac --release 8` (bytecode major version 52), so the same class file runs on every
# supported Java identifier. Source, for reference:
#
#   package probe;
#   public class HeapHandler {
#       static final String INIT_ID = UUID.randomUUID().toString();
#       static int CALLS = 0;
#       public Map<String, Object> handle(Map<String, Object> in) {
#           System.out.println("probe-env " + INIT_ID);
#           System.out.flush();
#           CALLS++;
#           int mb = ((Number) in.get("mb")).intValue();
#           List<byte[]> held = new ArrayList<>();
#           for (int i = 0; i < mb; i++) {
#               byte[] block = new byte[1024 * 1024];
#               for (int j = 0; j < block.length; j += 4096) block[j] = 1;
#               held.add(block);
#           }
#           Map<String, Object> out = new HashMap<>();
#           out.put("heldMb", held.size());
#           out.put("initId", INIT_ID);
#           out.put("calls", CALLS);
#           out.put("maxHeapBytes", Runtime.getRuntime().maxMemory());
#           return out;
#       }
#   }
_SHA256 = {
    "HeapHandler": "240233a9fa8dbff2ba487357fb241a394da7b947b9d91bf263bbe205c11f3800",
}

_B64 = {  # @@GENERATED@@ HeapHandler
    "HeapHandler":
        "yv66vgAAADQAfwoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCQAIAAkHAAoMAAsADAEA"
        "EGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsHAA4BABdqYXZhL2xhbmcvU3RyaW5nQnVp"
        "bGRlcgoADQADCAARAQAKcHJvYmUtZW52IAoADQATDAAUABUBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZh"
        "L2xhbmcvU3RyaW5nQnVpbGRlcjsJABcAGAcAGQwAGgAbAQARcHJvYmUvSGVhcEhhbmRsZXIBAAdJTklUX0lEAQASTGphdmEv"
        "bGFuZy9TdHJpbmc7CgANAB0MAB4AHwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsKACEAIgcAIwwAJAAlAQAT"
        "amF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYKACEAJwwAKAAGAQAFZmx1c2gJ"
        "ABcAKgwAKwAsAQAFQ0FMTFMBAAFJCAAuAQACbWILADAAMQcAMgwAMwA0AQANamF2YS91dGlsL01hcAEAA2dldAEAJihMamF2"
        "YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7BwA2AQAQamF2YS9sYW5nL051bWJlcgoANQA4DAA5ADoBAAhpbnRW"
        "YWx1ZQEAAygpSQcAPAEAE2phdmEvdXRpbC9BcnJheUxpc3QKADsAAwMAEAAACwBAAEEHAEIMAEMARAEADmphdmEvdXRpbC9M"
        "aXN0AQADYWRkAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaBwBGAQARamF2YS91dGlsL0hhc2hNYXAKAEUAAwgASQEABmhlbGRN"
        "YgsAQABLDABMADoBAARzaXplCgBOAE8HAFAMAFEAUgEAEWphdmEvbGFuZy9JbnRlZ2VyAQAHdmFsdWVPZgEAFihJKUxqYXZh"
        "L2xhbmcvSW50ZWdlcjsLADAAVAwAVQBWAQADcHV0AQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvT2JqZWN0OylM"
        "amF2YS9sYW5nL09iamVjdDsIAFgBAAZpbml0SWQIAFoBAAVjYWxscwgAXAEADG1heEhlYXBCeXRlcwoAXgBfBwBgDABhAGIB"
        "ABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsKAF4AZAwAZQBmAQAJbWF4"
        "TWVtb3J5AQADKClKCgBoAGkHAGoMAFEAawEADmphdmEvbGFuZy9Mb25nAQATKEopTGphdmEvbGFuZy9Mb25nOwoAbQBuBwBv"
        "DABwAHEBAA5qYXZhL3V0aWwvVVVJRAEACnJhbmRvbVVVSUQBABIoKUxqYXZhL3V0aWwvVVVJRDsKAG0AHQEABENvZGUBAA9M"
        "aW5lTnVtYmVyVGFibGUBAAZoYW5kbGUBACAoTGphdmEvdXRpbC9NYXA7KUxqYXZhL3V0aWwvTWFwOwEADVN0YWNrTWFwVGFi"
        "bGUHAHkBAAJbQgEACVNpZ25hdHVyZQEAbChMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09i"
        "amVjdDs+OylMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEACDxjbGluaXQ+"
        "AQAKU291cmNlRmlsZQEAEEhlYXBIYW5kbGVyLmphdmEAIQAXAAIAAAACABgAGgAbAAAACAArACwAAAADAAEABQAGAAEAcwAA"
        "AB0AAQABAAAABSq3AAGxAAAAAQB0AAAABgABAAAACQABAHUAdgACAHMAAAE4AAQABwAAAMeyAAe7AA1ZtwAPEhC2ABKyABa2"
        "ABK2ABy2ACCyAAe2ACayACkEYLMAKSsSLbkALwIAwAA1tgA3PbsAO1m3AD1OAzYEFQQcogAyEj68CDoFAzYGFQYZBb6iABIZ"
        "BRUGBFTEhAAGEACn/+wtGQW5AD8CAFeEBAGn/867AEVZtwBHOgQZBBJILbkASgEAuABNuQBTAwBXGQQSV7IAFrkAUwMAVxkE"
        "ElmyACm4AE25AFMDAFcZBBJbuABdtgBjuABnuQBTAwBXGQSwAAAAAgB0AAAAQgAQAAAADgAbAA8AIQAQACkAEQA4ABIAQAAT"
        "AEkAFABPABUAaQAWAHIAEwB4ABgAgQAZAJQAGgChABsAsQAcAMQAHQB3AAAAFwAE/gBDAQcAQAH9AA4HAHgB+gAW+QAOAHoA"
        "AAACAHsACAB8AAYAAQBzAAAAKgABAAAAAAAOuABstgByswAWA7MAKbEAAAABAHQAAAAKAAIAAAAKAAkACwABAH0AAAACAH4=",
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


def _invoker(ctx):
    """A Lambda client with standard retries; its read timeout outlasts every invoke it sends."""
    return ctx.client("lambda", config=Config(read_timeout=120, retries={"mode": "standard"}))


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


_ENV_LINE = re.compile(r"probe-env ([0-9a-f-]{36})")
#: Invokes after the OutOfMemoryError, none of which may land in the JVM that threw it.
_AFTER_OOM = 3


def _report_line(log, rid):
    lines = [ln for ln in log.splitlines() if ln.startswith(f"REPORT RequestId: {rid}")]
    assert len(lines) == 1, f"expected one REPORT line for request {rid!r} in the log tail: {log!r}"
    return lines[0]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """The JVM heap is bounded below MemorySize, and retaining memory past it fails as
    java.lang.OutOfMemoryError "Java heap space" with the handler's own stack frame and ends the
    JVM: its INIT_ID never serves another invoke.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    """
    invoker = _invoker(ctx)
    fn = ctx.unique_name("sim2real-behav-javaheap-")
    _function(ctx, FunctionName=fn, Runtime="java21", Handler="probe.HeapHandler::handle",
              Role=_execution_role(ctx), MemorySize=_MEMORY_SIZE_MB, Timeout=30,
              Code={"ZipFile": _zip({"probe/HeapHandler.class": _class_bytes("HeapHandler")})})

    r1 = _invoke(invoker, fn, json.dumps({"mb": _SMALL_MB}).encode())
    assert r1["error"] is None, f"positive control ({_SMALL_MB} MB) failed: {r1!r}"
    body1 = json.loads(r1["raw"])
    assert body1.get("heldMb") == _SMALL_MB and body1.get("calls") == 1, (
        f"positive control body: {body1!r}")
    max_heap = body1.get("maxHeapBytes")
    assert isinstance(max_heap, int) and 0 < max_heap < _MEMORY_SIZE_MB * 1024 * 1024, (
        f"the JVM heap must be bounded below MemorySize={_MEMORY_SIZE_MB} MB; Runtime.maxMemory() "
        f"was {max_heap!r}"
    )
    # Twice the heap bound: the loop can only end in OutOfMemoryError, never by completing.
    large_mb = 2 * (max_heap // (1024 * 1024))

    r2 = _invoke(invoker, fn, json.dumps({"mb": large_mb}).encode())
    assert r2["error"] == "Unhandled", (
        f"retaining {large_mb} MB must exhaust the {max_heap}-byte heap; FunctionError was "
        f"{r2['error']!r}: {r2['raw'][:400]!r}"
    )
    body2 = json.loads(r2["raw"])
    assert body2.get("errorType") == "java.lang.OutOfMemoryError", (
        f"exceeding the heap must report errorType java.lang.OutOfMemoryError, got {body2!r}"
    )
    assert body2.get("errorMessage") == "Java heap space", (
        f"errorMessage was {body2.get('errorMessage')!r}, expected the JVM's own 'Java heap space'"
    )
    trace = body2.get("stackTrace") or [None]
    assert isinstance(trace[0], str) and _FRAME.match(trace[0]), (
        f"stackTrace[0] was {trace[0]!r}; a heap OutOfMemoryError carries the handler's own "
        f"frame probe.HeapHandler.handle(HeapHandler.java:<line>), unlike a container-level kill, "
        f"which carries no Java stack trace at all"
    )
    assert "heldMb" not in body2, f"a heap-exhausted invoke still returned its result: {body2!r}"
    report = _report_line(r2["log"], r2["request_id"])
    assert "Error Type: Runtime.ExitError" in report.split("\t"), (
        f"the platform's own REPORT line must classify the process end as Runtime.ExitError — "
        f"distinct from the invoke body's own java.lang.OutOfMemoryError and from a "
        f"container-level kill's Runtime.OutOfMemory — but it read {report!r}"
    )
    envs = _ENV_LINE.findall(r2["log"])
    assert len(envs) == 1, f"the handler logs its INIT_ID once per invoke; the tail carried {envs!r}"
    exhausted = envs[0]

    for _ in range(_AFTER_OOM):
        r3 = _invoke(invoker, fn, json.dumps({"mb": _SMALL_MB}).encode())
        assert r3["error"] is None, f"invoke after the heap OOM failed: {r3!r}"
        body3 = json.loads(r3["raw"])
        assert body3.get("initId") != exhausted, (
            f"an invoke after the OutOfMemoryError ran in the JVM that threw it ({exhausted}): "
            f"{body3!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
