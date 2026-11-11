"""java17-request-stream-handler-gets-raw-bytes-and-a-context-naming-the-invocation."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java17-request-stream-handler-gets-raw-bytes-and-a-context-naming-the-invocation"
GROUP = "data-plane"
SERVICES = ["lambda"]

# probe.Stream implements RequestStreamHandler: it hashes the raw request bytes and writes back a
# JSON report of every Context getter. Compiled with `javac --release 17` against the interface
# the managed runtime provides; the bytecode is embedded and pinned by SHA-256.
JAVA_SOURCE = r'''
package probe;
public class Stream implements RequestStreamHandler {
    public void handleRequest(InputStream in, OutputStream out, Context c) throws IOException {
        byte[] raw = in.readAllBytes();                      // via transferTo
        // writes {"inLen","inSha256","requestId","functionName","functionVersion","invokedArn",
        //         "logGroup","logStream","memMb","remainingMs","javaSpec","handlerEnv"}
        System.out.println("PROBE-STREAM requestId=" + c.getAwsRequestId());
    }
}
'''

TIMEOUT_S = 20
MEMORY_MB = 512
# Deliberately not canonical JSON: odd spacing, a non-object top level and a non-ASCII string. A
# stream handler receives the bytes; a runtime that parses and re-serialises changes the hash.
PAYLOAD = '[1,  "zwölf" ,{"k" :null}, 2.50]'.encode("utf-8")
_STREAM = re.compile(r"^\d{4}/\d{2}/\d{2}/\[(?P<ver>[^\]]+)\][0-9a-f]{32}$")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A java17 RequestStreamHandler receives the payload's exact bytes and a Context naming the
    invocation: its request id, function, invoked version and ARN, log group and stream, memory,
    and a remaining time inside the configured timeout.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-context.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-java17-")
    created = _function(ctx, FunctionName=fn, Runtime="java17", Handler="probe.Stream",
                        Role=_execution_role(ctx), Code={"ZipFile": _deployment_zip()},
                        MemorySize=MEMORY_MB, Timeout=TIMEOUT_S)
    unqualified = created["FunctionArn"]

    r = _invoke(lam, fn, PAYLOAD)
    assert r["status"] == 200 and r["error"] is None, (
        f"$LATEST invoke failed: status={r['status']!r} error={r['error']!r} raw={r['raw'][:400]!r}")
    body = json.loads(r["raw"])
    assert body["inLen"] == len(PAYLOAD) and body["inSha256"] == hashlib.sha256(PAYLOAD).hexdigest(), (
        f"handler saw {body['inLen']!r} bytes hashing {body['inSha256']!r}; sent {len(PAYLOAD)} "
        f"bytes hashing {hashlib.sha256(PAYLOAD).hexdigest()!r}")
    assert body["requestId"] == r["request_id"], (
        f"Context.getAwsRequestId {body['requestId']!r} != Invoke response request id "
        f"{r['request_id']!r}")
    assert (body["functionName"], body["functionVersion"], body["invokedArn"]) == (
        fn, "$LATEST", unqualified), (
        f"Context names ({body['functionName']!r}, {body['functionVersion']!r}, "
        f"{body['invokedArn']!r}); expected the function, $LATEST and the unqualified ARN")
    assert body["logGroup"] == f"/aws/lambda/{fn}", f"log group {body['logGroup']!r}"
    m = _STREAM.match(body["logStream"])
    assert m and m["ver"] == "$LATEST", f"log stream {body['logStream']!r} is not a $LATEST stream"
    assert body["memMb"] == MEMORY_MB, f"getMemoryLimitInMB {body['memMb']!r} != {MEMORY_MB}"
    assert 0 < body["remainingMs"] <= TIMEOUT_S * 1000, (
        f"getRemainingTimeInMillis {body['remainingMs']!r} outside (0, {TIMEOUT_S * 1000}]")
    assert (body["javaSpec"], body["handlerEnv"]) == ("17", "probe.Stream"), (
        f"runtime reports java.specification.version={body['javaSpec']!r} "
        f"_HANDLER={body['handlerEnv']!r}")
    assert f"PROBE-STREAM requestId={r['request_id']}" in r["log"], (
        f"the handler's stdout line for this request is not in the log tail: {r['log'][-600:]!r}")

    version = lam.publish_version(FunctionName=fn)["Version"]
    _wait_active(lam, fn, version)
    q = _invoke(lam, fn, b'{"v":1}', qualifier=version)
    assert q["status"] == 200 and q["error"] is None, (
        f"version {version} invoke failed: {q['error']!r} {q['raw'][:400]!r}")
    vbody = json.loads(q["raw"])
    assert vbody["requestId"] == q["request_id"] != r["request_id"], (
        f"version invoke request ids: context {vbody['requestId']!r}, response "
        f"{q['request_id']!r}, first {r['request_id']!r}")
    assert (vbody["functionVersion"], vbody["invokedArn"]) == (version, f"{unqualified}:{version}"), (
        f"a version-{version} invoke reports version {vbody['functionVersion']!r} via "
        f"{vbody['invokedArn']!r}")
    vm = _STREAM.match(vbody["logStream"])
    assert vm and vm["ver"] == version, (
        f"version {version} ran in log stream {vbody['logStream']!r}")
    assert vbody["inSha256"] == hashlib.sha256(b'{"v":1}').hexdigest(), (
        f"version invoke hashed {vbody['inSha256']!r}")

_SHA256 = {
    "probe/Stream.class": "fa5f7c7910cbbe6a45148d2c09ef03b4f67dd0246bb0212a830bc4794fe2641e",
}

_B64 = {
    "probe/Stream.class":
        "yv66vgAAAD0ApwoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWBwAIAQAdamF2YS9p"
        "by9CeXRlQXJyYXlPdXRwdXRTdHJlYW0KAAcAAwoACwAMBwANDAAOAA8BABNqYXZhL2lvL0lucHV0U3RyZWFtAQAKdHJh"
        "bnNmZXJUbwEAGShMamF2YS9pby9PdXRwdXRTdHJlYW07KUoKAAcAEQwAEgATAQALdG9CeXRlQXJyYXkBAAQoKVtCBwAV"
        "AQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIKABQAAwgAGAEAB1NIQS0yNTYKABoAGwcAHAwAHQAeAQAbamF2YS9zZWN1"
        "cml0eS9NZXNzYWdlRGlnZXN0AQALZ2V0SW5zdGFuY2UBADEoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3NlY3VyaXR5"
        "L01lc3NhZ2VEaWdlc3Q7CgAaACAMACEAIgEABmRpZ2VzdAEABihbQilbQggAJAEABCUwMngKACYAJwcAKAwAKQAqAQAO"
        "amF2YS9sYW5nL0J5dGUBAAd2YWx1ZU9mAQATKEIpTGphdmEvbGFuZy9CeXRlOwoALAAtBwAuDAAvADABABBqYXZhL2xh"
        "bmcvU3RyaW5nAQAGZm9ybWF0AQA5KExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFu"
        "Zy9TdHJpbmc7CgAUADIMADMANAEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdC"
        "dWlsZGVyOwoAFAA2DAA3ADgBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7BwA6AQAmamF2YS9zZWN1cml0"
        "eS9Ob1N1Y2hBbGdvcml0aG1FeGNlcHRpb24HADwBABNqYXZhL2lvL0lPRXhjZXB0aW9uCgA7AD4MAAUAPwEAGChMamF2"
        "YS9sYW5nL1Rocm93YWJsZTspVgsAQQBCBwBDDABEADgBAC1jb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJkYS9ydW50"
        "aW1lL0NvbnRleHQBAA9nZXRBd3NSZXF1ZXN0SWQLAEEARgwARwA4AQAPZ2V0RnVuY3Rpb25OYW1lCwBBAEkMAEoAOAEA"
        "EmdldEZ1bmN0aW9uVmVyc2lvbgsAQQBMDABNADgBABVnZXRJbnZva2VkRnVuY3Rpb25Bcm4LAEEATwwAUAA4AQAPZ2V0"
        "TG9nR3JvdXBOYW1lCwBBAFIMAFMAOAEAEGdldExvZ1N0cmVhbU5hbWULAEEAVQwAVgBXAQASZ2V0TWVtb3J5TGltaXRJ"
        "bk1CAQADKClJCwBBAFkMAFoAVwEAGGdldFJlbWFpbmluZ1RpbWVJbk1pbGxpcwgAXAEAGmphdmEuc3BlY2lmaWNhdGlv"
        "bi52ZXJzaW9uCgBeAF8HAGAMAGEAYgEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAJihMamF2YS9sYW5n"
        "L1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7CABkAQAIX0hBTkRMRVIKAF4AZgwAZwBiAQAGZ2V0ZW52EgAAAGkMAGoA"
        "awEAF21ha2VDb25jYXRXaXRoQ29uc3RhbnRzAQC5KElMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztM"
        "amF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmlu"
        "ZztMamF2YS9sYW5nL1N0cmluZztJSUxqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5n"
        "L1N0cmluZzsJAF4AbQwAbgBvAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07EgABAHEMAGoAYgoAcwB0BwB1DAB2"
        "AHcBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgkAeQB6BwB7DAB8"
        "AH0BACFqYXZhL25pby9jaGFyc2V0L1N0YW5kYXJkQ2hhcnNldHMBAAVVVEZfOAEAGkxqYXZhL25pby9jaGFyc2V0L0No"
        "YXJzZXQ7CgAsAH8MAIAAgQEACGdldEJ5dGVzAQAeKExqYXZhL25pby9jaGFyc2V0L0NoYXJzZXQ7KVtCCgCDAIQHAIUM"
        "AIYAhwEAFGphdmEvaW8vT3V0cHV0U3RyZWFtAQAFd3JpdGUBAAUoW0IpVgcAiQEADHByb2JlL1N0cmVhbQcAiwEAOmNv"
        "bS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvUmVxdWVzdFN0cmVhbUhhbmRsZXIBAARDb2RlAQAPTGlu"
        "ZU51bWJlclRhYmxlAQANaGFuZGxlUmVxdWVzdAEAXShMamF2YS9pby9JbnB1dFN0cmVhbTtMamF2YS9pby9PdXRwdXRT"
        "dHJlYW07TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspVgEADVN0YWNrTWFwVGFi"
        "bGUHAJIBAAJbQgEACkV4Y2VwdGlvbnMBAApTb3VyY2VGaWxlAQALU3RyZWFtLmphdmEBABBCb290c3RyYXBNZXRob2Rz"
        "CACYAQC9eyJpbkxlbiI6ASwiaW5TaGEyNTYiOiIBIiwicmVxdWVzdElkIjoiASIsImZ1bmN0aW9uTmFtZSI6IgEiLCJm"
        "dW5jdGlvblZlcnNpb24iOiIBIiwiaW52b2tlZEFybiI6IgEiLCJsb2dHcm91cCI6IgEiLCJsb2dTdHJlYW0iOiIBIiwi"
        "bWVtTWIiOgEsInJlbWFpbmluZ01zIjoBLCJqYXZhU3BlYyI6IgEiLCJoYW5kbGVyRW52IjoiASJ9CACaAQAYUFJPQkUt"
        "U1RSRUFNIHJlcXVlc3RJZD0BDwYAnAoAnQCeBwCfDABqAKABACRqYXZhL2xhbmcvaW52b2tlL1N0cmluZ0NvbmNhdEZh"
        "Y3RvcnkBAJgoTGphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcyRMb29rdXA7TGphdmEvbGFuZy9TdHJpbmc7TGph"
        "dmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZh"
        "L2xhbmcvaW52b2tlL0NhbGxTaXRlOwEADElubmVyQ2xhc3NlcwcAowEAJWphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFu"
        "ZGxlcyRMb29rdXAHAKUBAB5qYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMBAAZMb29rdXAAIQCIAAIAAQCKAAAA"
        "AgABAAUABgABAIwAAAAdAAEAAQAAAAUqtwABsQAAAAEAjQAAAAYAAQAAAAwAAQCOAI8AAgCMAAABmAAMAAwAAADZuwAH"
        "WbcACToEKxkEtgAKWBkEtgAQOgW7ABRZtwAWOgcSF7gAGRkFtgAfOggZCL42CQM2ChUKFQmiACcZCBUKMzYLGQcSIwS9"
        "AAJZAxULuAAlU7gAK7YAMVeECgGn/9gZB7YANToGpwAPOge7ADtZGQe3AD2/GQW+GQYtuQBAAQAtuQBFAQAtuQBIAQAt"
        "uQBLAQAtuQBOAQAtuQBRAQAtuQBUAQAtuQBYAQASW7gAXRJjuABlugBoAAA6B7IAbC25AEABALoAcAAAtgByLBkHsgB4"
        "tgB+tgCCsQABABcAZgBpADkAAgCNAAAAVgAVAAAADgAJAA8AEAAQABcAEwAgABQAXwAVAGYAFgB1ABcAewAYAIEAGQCH"
        "ABoAjQAbAJMAHACZAB0AnwAeAKUAHwCsACAAsQAhALsAIgDMACMA2AAkAJAAAABJAAT/ADQACwcAiAcACwcAgwcAQQcA"
        "BwcAkQAHABQHAJEBAQAA+AAq/wAJAAYHAIgHAAsHAIMHAEEHAAcHAJEAAQcAOfwACwcALACTAAAABAABADsAAwCUAAAA"
        "AgCVAJYAAAAOAAIAmwABAJcAmwABAJkAoQAAAAoAAQCiAKQApgAZ",
}


def _deployment_zip() -> bytes:
    """The pinned bytecode, each entry checked against its SHA-256 before it is zipped."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, b64 in _B64.items():
            raw = base64.b64decode(b64)
            got = hashlib.sha256(raw).hexdigest()
            assert got == _SHA256[arc], (
                f"embedded artifact {arc!r} is sha256 {got!r}, pinned {_SHA256[arc]!r}")
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
