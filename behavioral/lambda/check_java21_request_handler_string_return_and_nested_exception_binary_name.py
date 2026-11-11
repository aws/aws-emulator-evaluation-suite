"""java21-request-handler-string-return-and-nested-exception-binary-name."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java21-request-handler-string-return-and-nested-exception-binary-name"
GROUP = "data-plane"
SERVICES = ["lambda"]

# probe.Fail implements RequestHandler<Map<String,Object>, String>. Compiled with
# `javac --release 17` against the interface the managed runtime provides; bytecode pinned below.
# JAVA_SOURCE is the exact compiled file, so the stackTrace line numbers below can be read off it.
JAVA_SOURCE = r'''
package probe;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import java.util.Map;

public class Fail implements RequestHandler<Map<String, Object>, String> {
    public static class Boom extends RuntimeException {
        public Boom(String msg, Throwable cause) { super(msg, cause); }
    }

    public String handleRequest(Map<String, Object> in, Context c) {
        Object mode = in == null ? null : in.get("mode");
        if ("wrapped".equals(mode)) {
            try {
                Integer.parseInt(String.valueOf(in.get("digits")));
                return "parsed";
            } catch (NumberFormatException e) {
                throw new Boom("outer-failure", e);
            }
        }
        if ("null".equals(mode)) return null;
        return "echo:" + in.get("word");
    }
}
'''


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A java21 RequestHandler returns a String as a JSON string and null as JSON null; a nested-class
    exception yields exactly errorType Outer$Inner, errorMessage and the handler and bridge frames,
    without the wrapped cause, and the environment then serves the next invoke.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-exceptions.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-java21-")
    _function(ctx, FunctionName=fn, Runtime="java21", Handler="probe.Fail",
              Role=_execution_role(ctx), Code={"ZipFile": _deployment_zip()},
              MemorySize=512, Timeout=20)

    ok = _invoke(lam, fn, json.dumps({"word": "grün"}).encode())
    assert ok["error"] is None and json.loads(ok["raw"]) == "echo:grün", (
        f"String return arrived as error={ok['error']!r} raw={ok['raw']!r}")
    nul = _invoke(lam, fn, b'{"mode": "null"}')
    assert nul["error"] is None and nul["raw"].strip() == b"null", (
        f"a null return arrived as error={nul['error']!r} raw={nul['raw']!r}")

    bad = _invoke(lam, fn, json.dumps({"mode": "wrapped", "digits": "12x"}).encode())
    assert bad["status"] == 200 and bad["error"] == "Unhandled", (
        f"wrapped failure returned status={bad['status']!r} FunctionError={bad['error']!r}")
    doc = json.loads(bad["raw"])
    assert (doc.get("errorType"), doc.get("errorMessage")) == ("probe.Fail$Boom", "outer-failure"), (
        f"error document names {doc.get('errorType')!r} / {doc.get('errorMessage')!r}")
    assert doc.get("stackTrace") == ["probe.Fail.handleRequest(Fail.java:19)",
                                     "probe.Fail.handleRequest(Fail.java:7)"], (
        f"stackTrace {doc.get('stackTrace')!r}")
    assert sorted(doc) == ["errorMessage", "errorType", "stackTrace"], (
        f"the error document carries keys {sorted(doc)!r}")

    again = _invoke(lam, fn, json.dumps({"word": "again"}).encode())
    assert again["error"] is None and json.loads(again["raw"]) == "echo:again", (
        f"invoke after the failure: error={again['error']!r} raw={again['raw']!r}")

_SHA256 = {
    "probe/Fail.class": "2951eb2844fa75f4eb1c4d38c7d579ab4a17fd6802eb96fe4d9f0707a3531b12",
    "probe/Fail$Boom.class": "d5071cd640398c8792f640695d87828cc25773f68c3356742ff12a7f2cb02455",
}

_B64 = {
    "probe/Fail.class":
        "yv66vgAAAD0AWwoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAEbW9kZQsA"
        "CgALBwAMDAANAA4BAA1qYXZhL3V0aWwvTWFwAQADZ2V0AQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09i"
        "amVjdDsIABABAAd3cmFwcGVkCgASABMHABQMABUAFgEAEGphdmEvbGFuZy9TdHJpbmcBAAZlcXVhbHMBABUoTGphdmEv"
        "bGFuZy9PYmplY3Q7KVoIABgBAAZkaWdpdHMKABIAGgwAGwAcAQAHdmFsdWVPZgEAJihMamF2YS9sYW5nL09iamVjdDsp"
        "TGphdmEvbGFuZy9TdHJpbmc7CgAeAB8HACAMACEAIgEAEWphdmEvbGFuZy9JbnRlZ2VyAQAIcGFyc2VJbnQBABUoTGph"
        "dmEvbGFuZy9TdHJpbmc7KUkIACQBAAZwYXJzZWQHACYBAB9qYXZhL2xhbmcvTnVtYmVyRm9ybWF0RXhjZXB0aW9uBwAo"
        "AQAPcHJvYmUvRmFpbCRCb29tCAAqAQANb3V0ZXItZmFpbHVyZQoAJwAsDAAFAC0BACooTGphdmEvbGFuZy9TdHJpbmc7"
        "TGphdmEvbGFuZy9UaHJvd2FibGU7KVYIAC8BAARudWxsCAAxAQAEd29yZBIAAAAzDAA0ADUBABdtYWtlQ29uY2F0V2l0"
        "aENvbnN0YW50cwEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7CgA3ADgHADkMADoAOwEACnBy"
        "b2JlL0ZhaWwBAA1oYW5kbGVSZXF1ZXN0AQBSKExqYXZhL3V0aWwvTWFwO0xjb20vYW1hem9uYXdzL3NlcnZpY2VzL2xh"
        "bWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL2xhbmcvU3RyaW5nOwcAPQEANGNvbS9hbWF6b25hd3Mvc2VydmljZXMv"
        "bGFtYmRhL3J1bnRpbWUvUmVxdWVzdEhhbmRsZXIBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQANU3RhY2tNYXBUYWJs"
        "ZQcAQgEALWNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dAEACVNpZ25hdHVyZQEAeChM"
        "amF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+O0xjb20vYW1hem9uYXdzL3Nl"
        "cnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL2xhbmcvU3RyaW5nOwEAVShMamF2YS9sYW5nL09iamVj"
        "dDtMY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9sYW1iZGEvcnVudGltZS9Db250ZXh0OylMamF2YS9sYW5nL09iamVjdDsB"
        "ABBNZXRob2RQYXJhbWV0ZXJzAQCRTGphdmEvbGFuZy9PYmplY3Q7TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRh"
        "L3J1bnRpbWUvUmVxdWVzdEhhbmRsZXI8TGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9P"
        "YmplY3Q7PjtMamF2YS9sYW5nL1N0cmluZzs+OwEAClNvdXJjZUZpbGUBAAlGYWlsLmphdmEBAAtOZXN0TWVtYmVycwEA"
        "EEJvb3RzdHJhcE1ldGhvZHMIAE0BAAZlY2hvOgEPBgBPCgBQAFEHAFIMADQAUwEAJGphdmEvbGFuZy9pbnZva2UvU3Ry"
        "aW5nQ29uY2F0RmFjdG9yeQEAmChMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cDtMamF2YS9sYW5n"
        "L1N0cmluZztMamF2YS9sYW5nL2ludm9rZS9NZXRob2RUeXBlO0xqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL09i"
        "amVjdDspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7AQAMSW5uZXJDbGFzc2VzAQAEQm9vbQcAVwEAJWphdmEvbGFu"
        "Zy9pbnZva2UvTWV0aG9kSGFuZGxlcyRMb29rdXAHAFkBAB5qYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMBAAZM"
        "b29rdXAAIQA3AAIAAQA8AAAAAwABAAUABgABAD4AAAAdAAEAAQAAAAUqtwABsQAAAAEAPwAAAAYAAQAAAAcAAQA6ADsA"
        "AgA+AAAAtwAEAAUAAABWK8cABwGnAAsrEge5AAkCAE4SDy22ABGZACMrEhe5AAkCALgAGbgAHVcSI7A6BLsAJ1kSKRkE"
        "twArvxIuLbYAEZkABQGwKxIwuQAJAgC4ABm6ADIAALAAAQAaACsALAAlAAIAPwAAACIACAAAAA0AEQAOABoAEAApABEA"
        "LAASAC4AEwA6ABYARQAXAEAAAAAfAAUIRwcAAv8AGwAEBwA3BwAKBwBBBwACAAEHACUNCgBDAAAAAgBEEEEAOgBFAAIA"
        "PgAAACIAAwADAAAACiorwAAKLLYANrAAAAABAD8AAAAGAAEAAAAHAEYAAAAJAgAAEAAAABAAAAUAQwAAAAIARwBIAAAA"
        "AgBJAEoAAAAEAAEAJwBLAAAACAABAE4AAQBMAFQAAAASAAIAJwA3AFUACQBWAFgAWgAZ",
    "probe/Fail$Boom.class":
        "yv66vgAAAD0AEgoAAgADBwAEDAAFAAYBABpqYXZhL2xhbmcvUnVudGltZUV4Y2VwdGlvbgEABjxpbml0PgEAKihMamF2"
        "YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1Rocm93YWJsZTspVgcACAEAD3Byb2JlL0ZhaWwkQm9vbQEABENvZGUBAA9M"
        "aW5lTnVtYmVyVGFibGUBAApTb3VyY2VGaWxlAQAJRmFpbC5qYXZhAQAITmVzdEhvc3QHAA8BAApwcm9iZS9GYWlsAQAM"
        "SW5uZXJDbGFzc2VzAQAEQm9vbQAhAAcAAgAAAAAAAQABAAUABgABAAkAAAAfAAMAAwAAAAcqKyy3AAGxAAAAAQAKAAAA"
        "BgABAAAACQADAAsAAAACAAwADQAAAAIADgAQAAAACgABAAcADgARAAk=",
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
