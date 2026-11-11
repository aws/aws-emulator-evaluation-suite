"""java-handler-string-resolves-context-overload-and-runs-a-static-method."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-handler-string-resolves-context-overload-and-runs-a-static-method"
GROUP = "data-plane"
SERVICES = ["lambda"]

# None of these three classes implements RequestHandler, so the "Class::method" handler string
# form applies and Lambda locates the method by name through reflection. probe.Over overloads
# mainHandler with and without a trailing Context parameter; probe.StaticOnly and probe.StaticCtx
# declare mainHandler STATIC rather than on an instance. Compiled once under JDK 8 (class file
# major version 52) against the aws-lambda-java-core Context type only.
JAVA_SOURCE_OVER = r'''
package probe;
import com.amazonaws.services.lambda.runtime.Context;
public class Over {
    public String mainHandler(String in, Context c) { return "instance-with-context:" + in; }
    public String mainHandler(String in) { return "instance-no-context:" + in; }
}
'''
JAVA_SOURCE_STATIC_ONLY = r'''
package probe;
public class StaticOnly {
    public static String mainHandler(String in) { return "static:" + in; }
}
'''
JAVA_SOURCE_STATIC_CTX = r'''
package probe;
import com.amazonaws.services.lambda.runtime.Context;
public class StaticCtx {
    public static String mainHandler(String in, Context c) {
        return "static-ctx:" + in + ":" + c.getFunctionName();
    }
}
'''

_SHA256 = {
    "probe/Over.class": "71df02c30fa8eddd87a1f01cab7abb4b39637f87fe5f0c0d27df123aff38c389",
    "probe/StaticOnly.class": "6db08bed3e75eb17003aafe5c45627c27990817171e505d47185537dcc8265e2",
    "probe/StaticCtx.class": "72399a7e2e57a45a9ebc642fa01c4c1c8e7f5e7be15f21f4c65fb5e373f9d251",
}

_B64 = {  # @@GENERATED@@ probe/Over.class probe/StaticOnly.class probe/StaticCtx.class
    "probe/Over.class":
        "yv66vgAAADQAHwoACQATBwAUCgACABMIABUKAAIAFgoAAgAXCAAYBwAZBwAaAQAGPGluaXQ+AQADKClWAQAEQ29kZQEA"
        "D0xpbmVOdW1iZXJUYWJsZQEAC21haW5IYW5kbGVyAQBVKExqYXZhL2xhbmcvU3RyaW5nO0xjb20vYW1hem9uYXdzL3Nl"
        "cnZpY2VzL2xhbWJkYS9ydW50aW1lL0NvbnRleHQ7KUxqYXZhL2xhbmcvU3RyaW5nOwEAJihMamF2YS9sYW5nL1N0cmlu"
        "ZzspTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEACU92ZXIuamF2YQwACgALAQAXamF2YS9sYW5nL1N0cmlu"
        "Z0J1aWxkZXIBABZpbnN0YW5jZS13aXRoLWNvbnRleHQ6DAAbABwMAB0AHgEAFGluc3RhbmNlLW5vLWNvbnRleHQ6AQAK"
        "cHJvYmUvT3ZlcgEAEGphdmEvbGFuZy9PYmplY3QBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xh"
        "bmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7ACEACAAJAAAAAAADAAEACgAL"
        "AAEADAAAAB0AAQABAAAABSq3AAGxAAAAAQANAAAABgABAAAABQABAA4ADwABAAwAAAAsAAIAAwAAABS7AAJZtwADEgS2"
        "AAUrtgAFtgAGsAAAAAEADQAAAAYAAQAAAAcAAQAOABAAAQAMAAAALAACAAIAAAAUuwACWbcAAxIHtgAFK7YABbYABrAA"
        "AAABAA0AAAAGAAEAAAALAAEAEQAAAAIAEg==",
    "probe/StaticOnly.class":
        "yv66vgAAADQAHAoACAARBwASCgACABEIABMKAAIAFAoAAgAVBwAWBwAXAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xp"
        "bmVOdW1iZXJUYWJsZQEAC21haW5IYW5kbGVyAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsB"
        "AApTb3VyY2VGaWxlAQAPU3RhdGljT25seS5qYXZhDAAJAAoBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgEAB3N0YXRp"
        "YzoMABgAGQwAGgAbAQAQcHJvYmUvU3RhdGljT25seQEAEGphdmEvbGFuZy9PYmplY3QBAAZhcHBlbmQBAC0oTGphdmEv"
        "bGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJp"
        "bmc7ACEABwAIAAAAAAACAAEACQAKAAEACwAAAB0AAQABAAAABSq3AAGxAAAAAQAMAAAABgABAAAAAwAJAA0ADgABAAsA"
        "AAAsAAIAAQAAABS7AAJZtwADEgS2AAUqtgAFtgAGsAAAAAEADAAAAAYAAQAAAAUAAQAPAAAAAgAQ",
    "probe/StaticCtx.class":
        "yv66vgAAADQAIwoACgATBwAUCgACABMIABUKAAIAFggAFwsAGAAZCgACABoHABsHABwBAAY8aW5pdD4BAAMoKVYBAARD"
        "b2RlAQAPTGluZU51bWJlclRhYmxlAQALbWFpbkhhbmRsZXIBAFUoTGphdmEvbGFuZy9TdHJpbmc7TGNvbS9hbWF6b25h"
        "d3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspTGphdmEvbGFuZy9TdHJpbmc7AQAKU291cmNlRmlsZQEA"
        "DlN0YXRpY0N0eC5qYXZhDAALAAwBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgEAC3N0YXRpYy1jdHg6DAAdAB4BAAE6"
        "BwAfDAAgACEMACIAIQEAD3Byb2JlL1N0YXRpY0N0eAEAEGphdmEvbGFuZy9PYmplY3QBAAZhcHBlbmQBAC0oTGphdmEv"
        "bGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAC1jb20vYW1hem9uYXdzL3NlcnZpY2VzL2xhbWJk"
        "YS9ydW50aW1lL0NvbnRleHQBAA9nZXRGdW5jdGlvbk5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACHRvU3RyaW5n"
        "ACEACQAKAAAAAAACAAEACwAMAAEADQAAAB0AAQABAAAABSq3AAGxAAAAAQAOAAAABgABAAAABQAJAA8AEAABAA0AAAA6"
        "AAIAAgAAACK7AAJZtwADEgS2AAUqtgAFEga2AAUruQAHAQC2AAW2AAiwAAAAAQAOAAAABgABAAAABwABABEAAAACABI=",
}


# ===== self-contained helpers =====
def _deployment_zip() -> bytes:
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
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _execution_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    policy = f"arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy),
                             "NoSuchEntity"))
    return arn


def _create(lam, kwargs, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "InvalidParameterValueException"
                           and "cannot be assumed by Lambda" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _wait_active(lam, fn, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    while True:
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Active":
            return cfg
        assert cfg["State"] != "Failed", f"{fn} entered State=Failed: {cfg.get('StateReason')!r}"
        assert time.monotonic() < deadline, f"{fn} did not reach Active within {timeout_s}s"
        time.sleep(2)


def _invoke(lam, fn, payload, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = (err.get("Code") == "AccessDeniedException"
                           and "cannot be assumed by Lambda" in err.get("Message", ""))
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{fn}: StatusCode {resp['StatusCode']!r} {raw!r}"
    return resp.get("FunctionError"), json.loads(raw)


def _function(ctx, lam, logs, **kwargs) -> str:
    fn = kwargs["FunctionName"]
    _create(lam, kwargs)
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn),
                             "ResourceNotFoundException"))
    _wait_active(lam, fn)
    return fn


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A non-interface 'Class::method' handler resolves an overloaded method NAME to the one
    taking a trailing Context over the one that does not, and a handler method may be static: a
    static method runs exactly like an instance one and still receives an injected Context.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _execution_role(ctx)
    zip_bytes = _deployment_zip()

    over_fn = ctx.unique_name("sim2real-behav-javaover-")
    over_fn = _function(ctx, lam, logs, FunctionName=over_fn, Runtime="java21",
                        Handler="probe.Over::mainHandler", Role=role_arn,
                        Code={"ZipFile": zip_bytes}, MemorySize=512, Timeout=20,
                        Tags={"sim2real": CHECK})

    static_fn = ctx.unique_name("sim2real-behav-javastatic-")
    static_fn = _function(ctx, lam, logs, FunctionName=static_fn, Runtime="java17.al2023",
                          Handler="probe.StaticOnly::mainHandler", Role=role_arn,
                          Code={"ZipFile": zip_bytes}, MemorySize=512, Timeout=20,
                          Tags={"sim2real": CHECK})

    staticctx_fn = ctx.unique_name("sim2real-behav-javastaticctx-")
    staticctx_fn = _function(ctx, lam, logs, FunctionName=staticctx_fn, Runtime="java11.al2023",
                             Handler="probe.StaticCtx::mainHandler", Role=role_arn,
                             Code={"ZipFile": zip_bytes}, MemorySize=512, Timeout=20,
                             Tags={"sim2real": CHECK})

    err, body = _invoke(lam, over_fn, "a")
    assert err is None, f"{over_fn}: FunctionError={err!r} body={body!r}"
    assert body == "instance-with-context:a", (
        f"probe.Over declares mainHandler(String) and mainHandler(String, Context) under the "
        f"same handler string; the handler resolved to {body!r}, not the Context-taking overload "
        f"'instance-with-context:a'")

    err2, body2 = _invoke(lam, static_fn, "b")
    assert err2 is None, f"{static_fn}: FunctionError={err2!r} body={body2!r}"
    assert body2 == "static:b", (
        f"a STATIC handler method must run exactly like an instance one; got "
        f"FunctionError={err2!r} body={body2!r}")

    err3, body3 = _invoke(lam, staticctx_fn, "c")
    assert err3 is None, f"{staticctx_fn}: FunctionError={err3!r} body={body3!r}"
    assert body3 == f"static-ctx:c:{staticctx_fn}", (
        f"a static handler's Context parameter must still be injected and name the function "
        f"itself; got {body3!r}, expected 'static-ctx:c:{staticctx_fn}'")

    # Repeat each on a second invoke: the resolution is not a cold-start fluke of the first call.
    err4, body4 = _invoke(lam, over_fn, "a2")
    assert err4 is None and body4 == "instance-with-context:a2", (
        f"overload resolution changed on a second invoke: FunctionError={err4!r} body={body4!r}")
    err5, body5 = _invoke(lam, static_fn, "b2")
    assert err5 is None and body5 == "static:b2", (
        f"static-method resolution changed on a second invoke: FunctionError={err5!r} body={body5!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
