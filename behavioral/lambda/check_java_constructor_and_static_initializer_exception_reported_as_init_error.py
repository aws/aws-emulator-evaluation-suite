"""java-constructor-and-static-initializer-exception-reported-as-init-error."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-constructor-and-static-initializer-exception-reported-as-init-error"
GROUP = "rejected"
SERVICES = ["lambda"]

# Three classes, none implementing RequestHandler (so no context is required): BadStaticInit's
# static initializer always throws, BadCtor's constructor always throws, and Good is the positive
# control. Compiled once under JDK 8 (class file major version 52), so these bytes need no
# recompilation to run under java17.al2023 or java21 below.
JAVA_SOURCE_BAD_STATIC_INIT = r'''
package probe;
public class BadStaticInit {
    static {
        if (Boolean.parseBoolean("true")) {
            throw new RuntimeException("probe-static-init-boom");
        }
    }
    public String mainHandler(String in) { return "unreachable"; }
}
'''
JAVA_SOURCE_BAD_CTOR = r'''
package probe;
public class BadCtor {
    public BadCtor() { throw new IllegalArgumentException("probe-ctor-boom"); }
    public String mainHandler(String in) { return "unreachable"; }
}
'''
JAVA_SOURCE_GOOD = r'''
package probe;
public class Good {
    public String mainHandler(String in) { return "ok:" + in; }
}
'''

_SHA256 = {
    "probe/BadStaticInit.class": "313b88ad45d59f7d9ecc611bdc381f5bdad299e53111835230a4280c8357f9f4",
    "probe/BadCtor.class": "e50b33fc34817754e2952486076a3f652f1f8ddd28bb2e53c83c15475fe9e63b",
    "probe/Good.class": "1be949a59df0f1a427d4c4ab6a1fff870cb54b2c99bb60b308862da2056f2687",
}

_B64 = {  # @@GENERATED@@ probe/BadStaticInit.class probe/BadCtor.class probe/Good.class
    "probe/BadStaticInit.class":
        "yv66vgAAADQAIgoACQAUCAAVCAAWCgAXABgHABkIABoKAAUAGwcAHAcAHQEABjxpbml0PgEAAygpVgEABENvZGUBAA9M"
        "aW5lTnVtYmVyVGFibGUBAAttYWluSGFuZGxlcgEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7"
        "AQAIPGNsaW5pdD4BAA1TdGFja01hcFRhYmxlAQAKU291cmNlRmlsZQEAEkJhZFN0YXRpY0luaXQuamF2YQwACgALAQAL"
        "dW5yZWFjaGFibGUBAAR0cnVlBwAeDAAfACABABpqYXZhL2xhbmcvUnVudGltZUV4Y2VwdGlvbgEAFnByb2JlLXN0YXRp"
        "Yy1pbml0LWJvb20MAAoAIQEAE3Byb2JlL0JhZFN0YXRpY0luaXQBABBqYXZhL2xhbmcvT2JqZWN0AQARamF2YS9sYW5n"
        "L0Jvb2xlYW4BAAxwYXJzZUJvb2xlYW4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBABUoTGphdmEvbGFuZy9TdHJpbmc7"
        "KVYAIQAIAAkAAAAAAAMAAQAKAAsAAQAMAAAAHQABAAEAAAAFKrcAAbEAAAABAA0AAAAGAAEAAAADAAEADgAPAAEADAAA"
        "ABsAAQACAAAAAxICsAAAAAEADQAAAAYAAQAAAAsACAAQAAsAAQAMAAAAPAADAAAAAAATEgO4AASZAA27AAVZEga3AAe/"
        "sQAAAAIADQAAAA4AAwAAAAUACAAGABIACAARAAAAAwABEgABABIAAAACABM=",
    "probe/BadCtor.class":
        "yv66vgAAADQAGAoABwAQBwARCAASCgACABMIABQHABUHABYBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJl"
        "clRhYmxlAQALbWFpbkhhbmRsZXIBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAClNvdXJj"
        "ZUZpbGUBAAxCYWRDdG9yLmphdmEMAAgACQEAImphdmEvbGFuZy9JbGxlZ2FsQXJndW1lbnRFeGNlcHRpb24BAA9wcm9i"
        "ZS1jdG9yLWJvb20MAAgAFwEAC3VucmVhY2hhYmxlAQANcHJvYmUvQmFkQ3RvcgEAEGphdmEvbGFuZy9PYmplY3QBABUo"
        "TGphdmEvbGFuZy9TdHJpbmc7KVYAIQAGAAcAAAAAAAIAAQAIAAkAAQAKAAAAKgADAAEAAAAOKrcAAbsAAlkSA7cABL8A"
        "AAABAAsAAAAKAAIAAAAEAAQABQABAAwADQABAAoAAAAbAAEAAgAAAAMSBbAAAAABAAsAAAAGAAEAAAAJAAEADgAAAAIA"
        "Dw==",
    "probe/Good.class":
        "yv66vgAAADQAHAoACAARBwASCgACABEIABMKAAIAFAoAAgAVBwAWBwAXAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xp"
        "bmVOdW1iZXJUYWJsZQEAC21haW5IYW5kbGVyAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsB"
        "AApTb3VyY2VGaWxlAQAJR29vZC5qYXZhDAAJAAoBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgEAA29rOgwAGAAZDAAa"
        "ABsBAApwcm9iZS9Hb29kAQAQamF2YS9sYW5nL09iamVjdAEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGph"
        "dmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsAIQAHAAgAAAAAAAIA"
        "AQAJAAoAAQALAAAAHQABAAEAAAAFKrcAAbEAAAABAAwAAAAGAAEAAAADAAEADQAOAAEACwAAACwAAgACAAAAFLsAAlm3"
        "AAMSBLYABSu2AAW2AAawAAAAAQAMAAAABgABAAAABQABAA8AAAACABA=",
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Java handler class whose static initializer or constructor throws never runs the handler
    body: every invoke fails with FunctionError=Unhandled and an errorType/errorMessage naming the
    failure, while a cleanly constructed class in the same package keeps serving.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _execution_role(ctx)
    zip_bytes = _deployment_zip()

    static_fn = ctx.unique_name("sim2real-behav-badstaticinit-")
    static_fn = _function(ctx, lam, logs, FunctionName=static_fn, Runtime="java17.al2023",
                          Handler="probe.BadStaticInit::mainHandler", Role=role_arn,
                          Code={"ZipFile": zip_bytes}, MemorySize=512, Timeout=20,
                          Tags={"sim2real": CHECK})

    ctor_fn = ctx.unique_name("sim2real-behav-badctor-")
    ctor_fn = _function(ctx, lam, logs, FunctionName=ctor_fn, Runtime="java21",
                        Handler="probe.BadCtor::mainHandler", Role=role_arn,
                        Code={"ZipFile": zip_bytes}, MemorySize=512, Timeout=20,
                        Tags={"sim2real": CHECK})

    good_fn = ctx.unique_name("sim2real-behav-goodctor-")
    good_fn = _function(ctx, lam, logs, FunctionName=good_fn, Runtime="java21",
                        Handler="probe.Good::mainHandler", Role=role_arn,
                        Code={"ZipFile": zip_bytes}, MemorySize=512, Timeout=20,
                        Tags={"sim2real": CHECK})

    # Positive control: a class that constructs cleanly runs its handler body every time.
    ok_err, ok_body = _invoke(lam, good_fn, "ping")
    assert ok_err is None and ok_body == "ok:ping", (
        f"the positive control did not run cleanly: FunctionError={ok_err!r} body={ok_body!r}")

    for _ in range(2):  # determinism: not a one-off cold-start artifact
        err, body = _invoke(lam, static_fn, "x")
        assert err == "Unhandled", (
            f"a static initializer that always throws returned FunctionError={err!r}, body={body!r}")
        assert body.get("errorType") == "java.lang.ExceptionInInitializerError", (
            f"errorType was {body.get('errorType')!r}; the JVM reports class-load failure under "
            f"java.lang.ExceptionInInitializerError regardless of the thrown cause's own type")
        assert body.get("errorMessage") == "Error loading class probe.BadStaticInit", (
            f"errorMessage was {body.get('errorMessage')!r}")
        assert {"errorMessage", "errorType"} <= set(body), (
            f"an init-phase failure reports errorType and errorMessage; got keys {sorted(body)!r}")

    for _ in range(2):
        err, body = _invoke(lam, ctor_fn, "x")
        assert err == "Unhandled", (
            f"a constructor that always throws returned FunctionError={err!r}, body={body!r}")
        assert body.get("errorType") == "java.lang.IllegalArgumentException", (
            f"errorType was {body.get('errorType')!r}; the constructor's own exception type must "
            f"be reported, not a generic wrapper")
        assert body.get("errorMessage") == "probe-ctor-boom", (
            f"errorMessage was {body.get('errorMessage')!r}, not the constructor's own message")
        assert {"errorMessage", "errorType"} <= set(body), (
            f"a constructor failure reports errorType and errorMessage; got keys {sorted(body)!r}")

    # Control, repeated after both failure classes: the handler-resolution cache for one broken
    # class does not poison an unrelated, successfully-constructed one.
    ok_err2, ok_body2 = _invoke(lam, good_fn, "pong")
    assert ok_err2 is None and ok_body2 == "ok:pong", (
        f"the positive control regressed after the two failure arms ran: "
        f"FunctionError={ok_err2!r} body={ok_body2!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
