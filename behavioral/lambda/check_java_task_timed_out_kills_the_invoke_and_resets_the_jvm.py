"""java-task-timed-out-kills-the-invoke-and-resets-the-jvm."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import time
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-task-timed-out-kills-the-invoke-and-resets-the-jvm"
GROUP = "java-packaging"
SERVICES = ["lambda"]

_TIMEOUT_S = 3
#: Comfortably inside the timeout; the second, way past it.
_SHORT_SLEEP_MS = 200
_LONG_SLEEP_MS = 8000

# Built with `javac --release 8` (bytecode major version 52), so the same class file runs on every
# supported Java identifier. Source, for reference:
#
#   package probe;
#   public class TimeoutHandler {
#       static final String INIT_ID = UUID.randomUUID().toString();
#       static int CALLS = 0;
#       public Map<String, Object> handle(Map<String, Object> in) throws InterruptedException {
#           System.out.println("probe-env " + INIT_ID);
#           System.out.flush();
#           long sleepMs = ((Number) in.get("sleepMs")).longValue();
#           Thread.sleep(sleepMs);
#           CALLS++;
#           Map<String, Object> out = new HashMap<>();
#           out.put("initId", INIT_ID);
#           out.put("calls", CALLS);
#           return out;
#       }
#   }
_SHA256 = {
    "TimeoutHandler": "eb0f40963c08fa9587f4a1fd72f5c412a440e8cdcbf09a20bf2638011a059011",
}

_B64 = {  # @@GENERATED@@ TimeoutHandler
    "TimeoutHandler":
        "yv66vgAAADQAZQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCQAIAAkHAAoMAAsADAEA"
        "EGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsHAA4BABdqYXZhL2xhbmcvU3RyaW5nQnVp"
        "bGRlcgoADQADCAARAQAKcHJvYmUtZW52IAoADQATDAAUABUBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZh"
        "L2xhbmcvU3RyaW5nQnVpbGRlcjsJABcAGAcAGQwAGgAbAQAUcHJvYmUvVGltZW91dEhhbmRsZXIBAAdJTklUX0lEAQASTGph"
        "dmEvbGFuZy9TdHJpbmc7CgANAB0MAB4AHwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsKACEAIgcAIwwAJAAl"
        "AQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYKACEAJwwAKAAGAQAFZmx1"
        "c2gIACoBAAdzbGVlcE1zCwAsAC0HAC4MAC8AMAEADWphdmEvdXRpbC9NYXABAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7"
        "KUxqYXZhL2xhbmcvT2JqZWN0OwcAMgEAEGphdmEvbGFuZy9OdW1iZXIKADEANAwANQA2AQAJbG9uZ1ZhbHVlAQADKClKCgA4"
        "ADkHADoMADsAPAEAEGphdmEvbGFuZy9UaHJlYWQBAAVzbGVlcAEABChKKVYJABcAPgwAPwBAAQAFQ0FMTFMBAAFJBwBCAQAR"
        "amF2YS91dGlsL0hhc2hNYXAKAEEAAwgARQEABmluaXRJZAsALABHDABIAEkBAANwdXQBADgoTGphdmEvbGFuZy9PYmplY3Q7"
        "TGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwgASwEABWNhbGxzCgBNAE4HAE8MAFAAUQEAEWphdmEvbGFu"
        "Zy9JbnRlZ2VyAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsKAFMAVAcAVQwAVgBXAQAOamF2YS91dGlsL1VV"
        "SUQBAApyYW5kb21VVUlEAQASKClMamF2YS91dGlsL1VVSUQ7CgBTAB0BAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQAGaGFu"
        "ZGxlAQAgKExqYXZhL3V0aWwvTWFwOylMamF2YS91dGlsL01hcDsBAApFeGNlcHRpb25zBwBfAQAeamF2YS9sYW5nL0ludGVy"
        "cnVwdGVkRXhjZXB0aW9uAQAJU2lnbmF0dXJlAQBsKExqYXZhL3V0aWwvTWFwPExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xh"
        "bmcvT2JqZWN0Oz47KUxqYXZhL3V0aWwvTWFwPExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0Oz47AQAIPGNs"
        "aW5pdD4BAApTb3VyY2VGaWxlAQATVGltZW91dEhhbmRsZXIuamF2YQAhABcAAgAAAAIAGAAaABsAAAAIAD8AQAAAAAMAAQAF"
        "AAYAAQBZAAAAHQABAAEAAAAFKrcAAbEAAAABAFoAAAAGAAEAAAAHAAEAWwBcAAMAWQAAAJ0AAwAFAAAAZbIAB7sADVm3AA8S"
        "ELYAErIAFrYAErYAHLYAILIAB7YAJisSKbkAKwIAwAAxtgAzQSC4ADeyAD0EYLMAPbsAQVm3AEM6BBkEEkSyABa5AEYDAFcZ"
        "BBJKsgA9uABMuQBGAwBXGQSwAAAAAQBaAAAAJgAJAAAADAAbAA0AIQAOADAADwA0ABAAPAARAEUAEgBSABMAYgAUAF0AAAAE"
        "AAEAXgBgAAAAAgBhAAgAYgAGAAEAWQAAACoAAQAAAAAADrgAUrYAWLMAFgOzAD2xAAAAAQBaAAAACgACAAAACAAJAAkAAQBj"
        "AAAAAgBk",
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


_ENV_LINE = re.compile(r"probe-env ([0-9a-f-]{36})")
#: Invokes after the kill, none of which may land in the killed JVM.
_AFTER_KILL = 4


def _invoke(lam, name, payload: bytes) -> dict:
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse", LogType="Tail",
                      Payload=payload)
    log = base64.b64decode(resp.get("LogResult", "")).decode("utf-8", "replace")
    return {"status": resp["StatusCode"], "error": resp.get("FunctionError"),
            "raw": resp["Payload"].read(), "request_id": resp["ResponseMetadata"]["RequestId"],
            "envs": _ENV_LINE.findall(log), "log": log}


def _short(invoker, fn) -> dict:
    r = _invoke(invoker, fn, json.dumps({"sleepMs": _SHORT_SLEEP_MS}).encode())
    assert r["error"] is None, f"a {_SHORT_SLEEP_MS}ms invoke failed: {r!r}"
    return json.loads(r["raw"])


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Java handler running past the configured Timeout is killed Sandbox.Timedout "Task timed
    out after N.00 seconds" with no Java stack trace: the killed JVM's INIT_ID never serves
    another invoke, and every newly initialised JVM's static call counter starts at 1.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html
    """
    invoker = _invoker(ctx)
    fn = ctx.unique_name("sim2real-behav-javatimeout-")
    _function(ctx, FunctionName=fn, Runtime="java21", Handler="probe.TimeoutHandler::handle",
              Role=_execution_role(ctx), MemorySize=512, Timeout=_TIMEOUT_S,
              Code={"ZipFile": _zip({"probe/TimeoutHandler.class": _class_bytes("TimeoutHandler")})})

    seen: dict[str, int] = {}

    def observe(body: dict) -> None:
        env, calls = body["initId"], body["calls"]
        if env in seen:
            assert calls == seen[env] + 1, (
                f"JVM {env} counted {calls} after {seen[env]}; a warm JVM keeps its static state")
        else:
            assert calls == 1, f"a newly initialised JVM {env} reported calls={calls}"
        seen[env] = calls

    observe(_short(invoker, fn))

    r2 = _invoke(invoker, fn, json.dumps({"sleepMs": _LONG_SLEEP_MS}).encode())
    assert r2["error"] == "Unhandled", (
        f"a {_LONG_SLEEP_MS}ms sleep must exceed Timeout={_TIMEOUT_S}s; FunctionError was "
        f"{r2['error']!r}: {r2['raw'][:300]!r}"
    )
    body2 = json.loads(r2["raw"])
    assert "stackTrace" not in body2, (
        f"a sandbox timeout kill carries no Java stack trace, got keys {sorted(body2)!r}"
    )
    assert body2.get("errorType") == "Sandbox.Timedout", f"errorType was {body2.get('errorType')!r}"
    want = f"RequestId: {r2['request_id']} Error: Task timed out after {_TIMEOUT_S}.00 seconds"
    assert body2.get("errorMessage") == want, (
        f"errorMessage was {body2.get('errorMessage')!r}, expected {want!r}"
    )
    assert len(r2["envs"]) == 1, (
        f"the timed-out handler prints its INIT_ID once before sleeping; the invoke's tail log "
        f"carried {r2['envs']!r}: {r2['log'][-600:]!r}"
    )
    killed = r2["envs"][0]

    for _ in range(_AFTER_KILL):
        body = _short(invoker, fn)
        assert body["initId"] != killed, (
            f"an invoke after the timeout ran in the killed JVM {killed}: {body!r}"
        )
        observe(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
