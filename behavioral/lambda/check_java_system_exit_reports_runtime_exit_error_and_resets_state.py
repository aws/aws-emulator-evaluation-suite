"""java-system-exit-reports-runtime-exit-error-and-resets-state."""
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

CHECK = "java-system-exit-reports-runtime-exit-error-and-resets-state"
GROUP = "java-packaging"
SERVICES = ["lambda"]

# Built with `javac --release 8` (bytecode major version 52), so the same class file runs on every
# supported Java identifier. Source, for reference:
#
#   package probe;
#   public class ExitHandler {
#       static final String INIT_ID = UUID.randomUUID().toString();
#       static int CALLS = 0;
#       public Map<String, Object> handle(Map<String, Object> in) {
#           if (in.get("exit") != null) {
#               System.out.println("probe-env " + INIT_ID);
#               System.out.flush();
#               System.exit(((Number) in.get("exit")).intValue());
#           }
#           CALLS++;
#           Map<String, Object> out = new HashMap<>();
#           out.put("initId", INIT_ID);
#           out.put("calls", CALLS);
#           return out;
#       }
#   }
_SHA256 = {
    "ExitHandler": "625491a9d15e3991512f8e399ae9825f629e8fbd32960f6241b3b9b69376c2d9",
}

_B64 = {  # @@GENERATED@@ ExitHandler
    "ExitHandler":
        "yv66vgAAADQAYAoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAEZXhpdAsACgAL"
        "BwAMDAANAA4BAA1qYXZhL3V0aWwvTWFwAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsJ"
        "ABAAEQcAEgwAEwAUAQAQamF2YS9sYW5nL1N5c3RlbQEAA291dAEAFUxqYXZhL2lvL1ByaW50U3RyZWFtOwcAFgEAF2phdmEv"
        "bGFuZy9TdHJpbmdCdWlsZGVyCgAVAAMIABkBAApwcm9iZS1lbnYgCgAVABsMABwAHQEABmFwcGVuZAEALShMamF2YS9sYW5n"
        "L1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwkAHwAgBwAhDAAiACMBABFwcm9iZS9FeGl0SGFuZGxlcgEAB0lO"
        "SVRfSUQBABJMamF2YS9sYW5nL1N0cmluZzsKABUAJQwAJgAnAQAIdG9TdHJpbmcBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwoA"
        "KQAqBwArDAAsAC0BABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgoAKQAv"
        "DAAwAAYBAAVmbHVzaAcAMgEAEGphdmEvbGFuZy9OdW1iZXIKADEANAwANQA2AQAIaW50VmFsdWUBAAMoKUkKABAAOAwACAA5"
        "AQAEKEkpVgkAHwA7DAA8AD0BAAVDQUxMUwEAAUkHAD8BABFqYXZhL3V0aWwvSGFzaE1hcAoAPgADCABCAQAGaW5pdElkCwAK"
        "AEQMAEUARgEAA3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7"
        "CABIAQAFY2FsbHMKAEoASwcATAwATQBOAQARamF2YS9sYW5nL0ludGVnZXIBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9J"
        "bnRlZ2VyOwoAUABRBwBSDABTAFQBAA5qYXZhL3V0aWwvVVVJRAEACnJhbmRvbVVVSUQBABIoKUxqYXZhL3V0aWwvVVVJRDsK"
        "AFAAJQEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAZoYW5kbGUBACAoTGphdmEvdXRpbC9NYXA7KUxqYXZhL3V0aWwvTWFw"
        "OwEADVN0YWNrTWFwVGFibGUBAAlTaWduYXR1cmUBAGwoTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEv"
        "bGFuZy9PYmplY3Q7PjspTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9PYmplY3Q7PjsBAAg8"
        "Y2xpbml0PgEAClNvdXJjZUZpbGUBABBFeGl0SGFuZGxlci5qYXZhACEAHwACAAAAAgAYACIAIwAAAAgAPAA9AAAAAwABAAUA"
        "BgABAFYAAAAdAAEAAQAAAAUqtwABsQAAAAEAVwAAAAYAAQAAAAcAAQBYAFkAAgBWAAAAqwADAAMAAABqKxIHuQAJAgDGADWy"
        "AA+7ABVZtwAXEhi2ABqyAB62ABq2ACS2ACiyAA+2AC4rEge5AAkCAMAAMbYAM7gAN7IAOgRgswA6uwA+WbcAQE0sEkGyAB65"
        "AEMDAFcsEkeyADq4AEm5AEMDAFcssAAAAAIAVwAAACYACQAAAAwACwANACYADgAsAA8APQARAEUAEgBNABMAWQAUAGgAFQBa"
        "AAAAAwABPQBbAAAAAgBcAAgAXQAGAAEAVgAAACoAAQAAAAAADrgAT7YAVbMAHgOzADqxAAAAAQBXAAAACgACAAAACAAJAAkA"
        "AQBeAAAAAgBf",
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


_ENV_LINE = re.compile(r"probe-env ([0-9a-f-]{36})")
#: Ordinary invokes that may pass before one repeats an environment; AWS reuses a warm one in
#: practice, so a repeat within this bound is the positive control for reuse.
_REUSE_TRIES = 8
#: Ordinary invokes after an exit, none of which may land in the exited JVM.
_AFTER_EXIT = 4


def _ordinary(lam, fn) -> dict:
    r = _invoke(lam, fn, b"{}")
    assert r["error"] is None, f"an ordinary invoke failed: {r!r}"
    return json.loads(r["raw"])


def _died(lam, fn, exit_code):
    r = _invoke(lam, fn, json.dumps({"exit": exit_code}).encode())
    assert r["status"] == 200, f"exit={exit_code}: StatusCode {r['status']!r}"
    assert r["error"] == "Unhandled", (
        f"exit={exit_code}: FunctionError={r['error']!r}, expected 'Unhandled'; body "
        f"{r['raw'][:300]!r}"
    )
    found = _ENV_LINE.findall(r["log"])
    assert len(found) == 1, (
        f"exit={exit_code}: the exiting handler prints its INIT_ID once before System.exit; the "
        f"invoke's tail log carried {found!r}: {r['log'][-600:]!r}"
    )
    return r, json.loads(r["raw"]), found[0]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Java handler calling System.exit ends its JVM with Runtime.ExitError "RequestId: <id> Error:
    Runtime exited with error: exit status N": the exited JVM's INIT_ID never serves another invoke
    and every newly initialised JVM's static call counter starts at 1.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/troubleshooting-execution.html
    """
    lam = ctx.client("lambda", config=Config(read_timeout=120, retries={"mode": "standard"}))
    fn = ctx.unique_name("sim2real-behav-javaexit-")
    _function(ctx, FunctionName=fn, Runtime="java21", Handler="probe.ExitHandler::handle",
              Role=_execution_role(ctx), MemorySize=512, Timeout=20,
              Code={"ZipFile": _zip({"probe/ExitHandler.class": _class_bytes("ExitHandler")})})

    seen: dict[str, int] = {}

    def observe(body: dict) -> None:
        env, calls = body["initId"], body["calls"]
        if env in seen:
            assert calls == seen[env] + 1, (
                f"JVM {env} counted {calls} after {seen[env]}; a warm JVM keeps its static state")
        else:
            assert calls == 1, f"a newly initialised JVM {env} reported calls={calls}"
        seen[env] = calls

    reused = False
    for _ in range(_REUSE_TRIES):
        body = _ordinary(lam, fn)
        reused = reused or body["initId"] in seen
        observe(body)
        if reused:
            break
    assert reused, (
        f"{_REUSE_TRIES} sequential invokes each ran in a different JVM ({sorted(seen)!r}); a "
        f"warm environment is never reused, so the exit's reset below proves nothing"
    )

    for exit_code in (1, 3):
        r, body, exited = _died(lam, fn, exit_code)
        assert body.get("errorType") == "Runtime.ExitError", (
            f"exit={exit_code}: errorType {body.get('errorType')!r}, expected 'Runtime.ExitError'"
        )
        want = f"RequestId: {r['request_id']} Error: Runtime exited with error: exit status {exit_code}"
        assert body.get("errorMessage") == want, (
            f"exit={exit_code}: errorMessage {body.get('errorMessage')!r}, expected {want!r}"
        )
        for _ in range(_AFTER_EXIT):
            after = _ordinary(lam, fn)
            assert after["initId"] != exited, (
                f"after exit={exit_code} an invoke ran in the exited JVM {exited}: {after!r}"
            )
            observe(after)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
