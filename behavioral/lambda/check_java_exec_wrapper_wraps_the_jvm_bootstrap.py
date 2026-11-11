"""java-exec-wrapper-wraps-the-jvm-bootstrap."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-exec-wrapper-wraps-the-jvm-bootstrap"
GROUP = "java-packaging"
SERVICES = ["lambda"]

_WRAPPER = """\
#!/bin/bash
printf '%s\\n' "$@" > /tmp/wrapper-argv
export PROBE_WRAPPED="set-by-wrapper"
exec "$@"
"""

# Built with `javac` under Amazon Corretto 8 (bytecode major version 52), so the same class file
# runs on every supported Java identifier. Source, for reference:
#
#   package probe;
#   public class WrapperHandler {
#       public Map<String, Object> handle(Map<String, Object> in) throws Exception {
#           Map<String, Object> out = new HashMap<>();
#           out.put("wrapped", System.getenv("PROBE_WRAPPED"));
#           out.put("wrapperEnv", System.getenv("AWS_LAMBDA_EXEC_WRAPPER"));
#           Path argvFile = Paths.get("/tmp/wrapper-argv");
#           if (Files.exists(argvFile)) {
#               List<String> lines = Files.readAllLines(argvFile);
#               out.put("argv0", lines.isEmpty() ? null : lines.get(0));
#           } else { out.put("argv0", null); }
#           return out;
#       }
#   }
_SHA256 = {
    "WrapperHandler": "ba4ec5e2370f299d4520da773a2b9f329218e0d50316fed6b44673382d79548b",
}

_B64 = {  # @@GENERATED@@ WrapperHandler
    "WrapperHandler":
        "yv66vgAAADQAVAoAFAAoBwApCgACACgIACoIACsKACwALQsALgAvCAAwCAAxCAAyBwAzCgA0ADUHADYKADcAOAoANwA5CAA6"
        "CwA7ADwLADsAPQcAPgcAPwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAZoYW5kbGUBACAoTGph"
        "dmEvdXRpbC9NYXA7KUxqYXZhL3V0aWwvTWFwOwEADVN0YWNrTWFwVGFibGUHAD4HAEAHAEEHAEIHADMHAD8BAApFeGNlcHRp"
        "b25zBwBDAQAJU2lnbmF0dXJlAQBsKExqYXZhL3V0aWwvTWFwPExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0"
        "Oz47KUxqYXZhL3V0aWwvTWFwPExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0Oz47AQAKU291cmNlRmlsZQEA"
        "E1dyYXBwZXJIYW5kbGVyLmphdmEMABUAFgEAEWphdmEvdXRpbC9IYXNoTWFwAQAHd3JhcHBlZAEADVBST0JFX1dSQVBQRUQH"
        "AEQMAEUARgcAQAwARwBIAQAKd3JhcHBlckVudgEAF0FXU19MQU1CREFfRVhFQ19XUkFQUEVSAQARL3RtcC93cmFwcGVyLWFy"
        "Z3YBABBqYXZhL2xhbmcvU3RyaW5nBwBJDABKAEsBABhqYXZhL25pby9maWxlL0xpbmtPcHRpb24HAEwMAE0ATgwATwBQAQAF"
        "YXJndjAHAEIMAFEAUgwASgBTAQAUcHJvYmUvV3JhcHBlckhhbmRsZXIBABBqYXZhL2xhbmcvT2JqZWN0AQANamF2YS91dGls"
        "L01hcAEAEmphdmEvbmlvL2ZpbGUvUGF0aAEADmphdmEvdXRpbC9MaXN0AQATamF2YS9sYW5nL0V4Y2VwdGlvbgEAEGphdmEv"
        "bGFuZy9TeXN0ZW0BAAZnZXRlbnYBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAA3B1dAEAOChM"
        "amF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQATamF2YS9uaW8vZmlsZS9Q"
        "YXRocwEAA2dldAEAOyhMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL25pby9maWxlL1BhdGg7"
        "AQATamF2YS9uaW8vZmlsZS9GaWxlcwEABmV4aXN0cwEAMihMamF2YS9uaW8vZmlsZS9QYXRoO1tMamF2YS9uaW8vZmlsZS9M"
        "aW5rT3B0aW9uOylaAQAMcmVhZEFsbExpbmVzAQAmKExqYXZhL25pby9maWxlL1BhdGg7KUxqYXZhL3V0aWwvTGlzdDsBAAdp"
        "c0VtcHR5AQADKClaAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7ACEAEwAUAAAAAAACAAEAFQAWAAEAFwAAAB0AAQABAAAABSq3"
        "AAGxAAAAAQAYAAAABgABAAAACgABABkAGgADABcAAADwAAQABQAAAG27AAJZtwADTSwSBBIFuAAGuQAHAwBXLBIIEgm4AAa5"
        "AAcDAFcSCgO9AAu4AAxOLQO9AA24AA6ZACstuAAPOgQsEhAZBLkAEQEAmQAHAacACxkEA7kAEgIAuQAHAwBXpwANLBIQAbkA"
        "BwMAVyywAAAAAgAYAAAAKgAKAAAADAAIAA0AFgAOACQADwAuABAAOQARAD8AEgBeABMAYQAUAGsAFgAbAAAAQQAE/wBQAAUH"
        "ABwHAB0HAB0HAB4HAB8AAgcAHQcAIP8ABwAFBwAcBwAdBwAdBwAeBwAfAAMHAB0HACAHACH6AAgJACIAAAAEAAEAIwAkAAAA"
        "AgAlAAEAJgAAAAIAJw==",
}


def _class_bytes(key: str) -> bytes:
    raw = base64.b64decode(_B64[key])
    got = hashlib.sha256(raw).hexdigest()
    assert got == _SHA256[key], (
        f"embedded class {key!r} is sha256 {got!r}, pinned {_SHA256[key]!r} — the bytecode under "
        f"test is not the bytecode this check was verified against"
    )
    return raw


def _zip(files: dict) -> bytes:
    """A zip of ``{arcname: (bytes_or_text, mode)}``; the mode lands in the Unix permission bits."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, (content, mode) in files.items():
            info = zipfile.ZipInfo(arc, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            data = content if isinstance(content, bytes) else textwrap.dedent(content).encode()
            zf.writestr(info, data)
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


def _invoke(lam, name, payload: bytes) -> dict:
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse", Payload=payload)
    return {"status": resp["StatusCode"], "error": resp.get("FunctionError"),
            "raw": resp["Payload"].read()}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """AWS_LAMBDA_EXEC_WRAPPER wraps the java Runtime's own bootstrap: the wrapper receives the
    JVM invocation as its arguments and its export reaches the handler; removing the variable
    starts the next environment without it.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/runtimes-modify.html#runtime-wrapper
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-javawrap-")
    wrapper_path = "/var/task/wrap.sh"
    _function(ctx, FunctionName=fn, Runtime="java21", Handler="probe.WrapperHandler::handle",
              Role=_execution_role(ctx), MemorySize=512, Timeout=20,
              Code={"ZipFile": _zip({
                  "probe/WrapperHandler.class": (_class_bytes("WrapperHandler"), 0o644),
                  "wrap.sh": (_WRAPPER, 0o755),
              })},
              Environment={"Variables": {"AWS_LAMBDA_EXEC_WRAPPER": wrapper_path}})

    r = _invoke(lam, fn, b"{}")
    assert r["error"] is None, f"wrapped invoke failed: {r['error']!r} {r['raw'][:400]!r}"
    body = json.loads(r["raw"])
    assert body["wrapped"] == "set-by-wrapper", (
        f"the wrapper's export is not in the handler's environment: {body!r}")
    assert body["wrapperEnv"] == wrapper_path, f"AWS_LAMBDA_EXEC_WRAPPER={body['wrapperEnv']!r}"
    argv0 = body.get("argv0") or ""
    assert argv0.endswith("/bin/java"), (
        f"the wrapper's first argument must be the java Runtime's own bootstrap executable "
        f"— got argv0={argv0!r}"
    )

    # The runtime's serializer omits null-valued Map entries entirely, so an all-null response
    # body is "{}" — absence, not an explicit null, is what "removed" looks like.
    lam.update_function_configuration(FunctionName=fn, Environment={"Variables": {}})
    _wait_active(lam, fn)
    r2 = _poll(lambda: _invoke(lam, fn, b"{}"),
               lambda r: "wrapperEnv" not in json.loads(r["raw"]),
               timeout_s=90, interval_s=3, what="the removed AWS_LAMBDA_EXEC_WRAPPER takes effect")
    assert r2["error"] is None, f"unwrapped invoke failed: {r2['error']!r}"
    body2 = json.loads(r2["raw"])
    assert body2.get("wrapped") is None and body2.get("wrapperEnv") is None, (
        f"without AWS_LAMBDA_EXEC_WRAPPER the environment still shows the wrapper: {body2!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
