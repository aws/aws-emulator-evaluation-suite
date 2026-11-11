"""java-family-matrix-one-class-tree-runs-identically-on-every-supported-identifier."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "java-family-matrix-one-class-tree-runs-identically-on-every-supported-identifier"
GROUP = "data-plane"
SERVICES = ["lambda"]

# probe.Matrix does not implement RequestHandler, so its Map<String,Object> input binds through
# the runtime's default Jackson configuration, and probe.In is its POJO shape. Compiled once with
# `javac` under JDK 8 (class file major version 52 -- the oldest format every java* identifier
# below accepts), so the SAME bytes are deployed under every identifier with no recompilation.
JAVA_SOURCE_IN = r'''
package probe;
import java.util.List;
public class In {
    public String mode;
    public int n;
    public List<String> items;
}
'''
JAVA_SOURCE_MATRIX = r'''
package probe;
import com.amazonaws.services.lambda.runtime.Context;
import java.util.LinkedHashMap;
import java.util.Map;

// THROW_FRAME pins the throw statement below to line 11 of this file.

public class Matrix {
    public Map<String, Object> mainHandler(In in, Context ctx) {
        if (in != null && "throw".equals(in.mode)) {
            throw new IllegalStateException("probe-matrix-failure");
        }
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("javaSpecVersion", System.getProperty("java.specification.version"));
        out.put("javaVmName", System.getProperty("java.vm.name"));
        out.put("osArch", System.getProperty("os.arch"));
        out.put("nPlusOne", (in == null ? 0 : in.n) + 1);
        out.put("items", in == null ? null : in.items);
        out.put("itemCount", in == null || in.items == null ? 0 : in.items.size());
        out.put("functionName", ctx.getFunctionName());
        out.put("awsRequestId", ctx.getAwsRequestId());
        out.put("remainingMs", ctx.getRemainingTimeInMillis());
        out.put("memLimitMb", ctx.getMemoryLimitInMB());
        return out;
    }
}
'''

_SHA256 = {
    "probe/In.class": "ae467060d3cff1e085e2b486f5926e3ef05110332a5a28aed903b08ce0f41fb6",
    "probe/Matrix.class": "f86928ef04183ecfac21f01597ec25e50ad0804941719a1e4ae8a892f2468b7e",
}

_B64 = {  # @@GENERATED@@ probe/In.class probe/Matrix.class
    "probe/In.class":
        "yv66vgAAADQAFQoAAwASBwATBwAUAQAEbW9kZQEAEkxqYXZhL2xhbmcvU3RyaW5nOwEAAW4BAAFJAQAFaXRlbXMBABBM"
        "amF2YS91dGlsL0xpc3Q7AQAJU2lnbmF0dXJlAQAkTGphdmEvdXRpbC9MaXN0PExqYXZhL2xhbmcvU3RyaW5nOz47AQAG"
        "PGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAClNvdXJjZUZpbGUBAAdJbi5qYXZhDAAMAA0BAAhw"
        "cm9iZS9JbgEAEGphdmEvbGFuZy9PYmplY3QAIQACAAMAAAADAAEABAAFAAAAAQAGAAcAAAABAAgACQABAAoAAAACAAsA"
        "AQABAAwADQABAA4AAAAdAAEAAQAAAAUqtwABsQAAAAEADwAAAAYAAQAAAAUAAQAQAAAAAgAR",
    "probe/Matrix.class":
        "yv66vgAAADQAeAoAIgA0CAA1CQA2ADcKADgAOQcAOggAOwoABQA8BwA9CgAIADQIAD4IAD8KAEAAQQsAQgBDCABECABF"
        "CABGCABHCABICQA2AEkKAEoASwgATAkANgBNCABOCwBPAFAIAFELAFIAUwgAVAsAUgBVCABWCwBSAFcIAFgLAFIAWQcA"
        "WgcAWwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAttYWluSGFuZGxlcgEASihMcHJvYmUv"
        "SW47TGNvbS9hbWF6b25hd3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspTGphdmEvdXRpbC9NYXA7AQAN"
        "U3RhY2tNYXBUYWJsZQcAWgcAXAcAXQcAXgcAXwcAWwEACVNpZ25hdHVyZQEAcChMcHJvYmUvSW47TGNvbS9hbWF6b25h"
        "d3Mvc2VydmljZXMvbGFtYmRhL3J1bnRpbWUvQ29udGV4dDspTGphdmEvdXRpbC9NYXA8TGphdmEvbGFuZy9TdHJpbmc7"
        "TGphdmEvbGFuZy9PYmplY3Q7PjsBAApTb3VyY2VGaWxlAQALTWF0cml4LmphdmEMACMAJAEABXRocm93BwBcDABgAGEH"
        "AF8MAGIAYwEAH2phdmEvbGFuZy9JbGxlZ2FsU3RhdGVFeGNlcHRpb24BABRwcm9iZS1tYXRyaXgtZmFpbHVyZQwAIwBk"
        "AQAXamF2YS91dGlsL0xpbmtlZEhhc2hNYXABAA9qYXZhU3BlY1ZlcnNpb24BABpqYXZhLnNwZWNpZmljYXRpb24udmVy"
        "c2lvbgcAZQwAZgBnBwBeDABoAGkBAApqYXZhVm1OYW1lAQAMamF2YS52bS5uYW1lAQAGb3NBcmNoAQAHb3MuYXJjaAEA"
        "CG5QbHVzT25lDABqAGsHAGwMAG0AbgEABWl0ZW1zDABMAG8BAAlpdGVtQ291bnQHAHAMAHEAcgEADGZ1bmN0aW9uTmFt"
        "ZQcAXQwAcwB0AQAMYXdzUmVxdWVzdElkDAB1AHQBAAtyZW1haW5pbmdNcwwAdgByAQAKbWVtTGltaXRNYgwAdwByAQAM"
        "cHJvYmUvTWF0cml4AQAQamF2YS9sYW5nL09iamVjdAEACHByb2JlL0luAQAtY29tL2FtYXpvbmF3cy9zZXJ2aWNlcy9s"
        "YW1iZGEvcnVudGltZS9Db250ZXh0AQANamF2YS91dGlsL01hcAEAEGphdmEvbGFuZy9TdHJpbmcBAARtb2RlAQASTGph"
        "dmEvbGFuZy9TdHJpbmc7AQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAVKExqYXZhL2xhbmcvU3RyaW5n"
        "OylWAQAQamF2YS9sYW5nL1N5c3RlbQEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5n"
        "L1N0cmluZzsBAANwdXQBADgoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2Jq"
        "ZWN0OwEAAW4BAAFJAQARamF2YS9sYW5nL0ludGVnZXIBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwEA"
        "EExqYXZhL3V0aWwvTGlzdDsBAA5qYXZhL3V0aWwvTGlzdAEABHNpemUBAAMoKUkBAA9nZXRGdW5jdGlvbk5hbWUBABQo"
        "KUxqYXZhL2xhbmcvU3RyaW5nOwEAD2dldEF3c1JlcXVlc3RJZAEAGGdldFJlbWFpbmluZ1RpbWVJbk1pbGxpcwEAEmdl"
        "dE1lbW9yeUxpbWl0SW5NQgAhACEAIgAAAAAAAgABACMAJAABACUAAAAdAAEAAQAAAAUqtwABsQAAAAEAJgAAAAYAAQAA"
        "AAgAAQAnACgAAgAlAAAB7AAEAAQAAADjK8YAGRICK7QAA7YABJkADbsABVkSBrcAB7+7AAhZtwAJTi0SChILuAAMuQAN"
        "AwBXLRIOEg+4AAy5AA0DAFctEhASEbgADLkADQMAVy0SEivHAAcDpwAHK7QAEwRguAAUuQANAwBXLRIVK8cABwGnAAcr"
        "tAAWuQANAwBXLRIXK8YACiu0ABbHAAcDpwAMK7QAFrkAGAEAuAAUuQANAwBXLRIZLLkAGgEAuQANAwBXLRIbLLkAHAEA"
        "uQANAwBXLRIdLLkAHgEAuAAUuQANAwBXLRIfLLkAIAEAuAAUuQANAwBXLbAAAAACACYAAAA6AA4AAAAKABAACwAaAA0A"
        "IgAOADAADwA+ABAATAARAGYAEgB7ABMAnwAUAK4AFQC9ABYAzwAXAOEAGAApAAAAtwAIGv8APAAEBwAqBwArBwAsBwAt"
        "AAIHAC0HAC7/AAMABAcAKgcAKwcALAcALQADBwAtBwAuAf8AFQAEBwAqBwArBwAsBwAtAAIHAC0HAC7/AAMABAcAKgcA"
        "KwcALAcALQADBwAtBwAuBwAv/wATAAQHACoHACsHACwHAC0AAgcALQcALv8AAwAEBwAqBwArBwAsBwAtAAIHAC0HAC7/"
        "AAgABAcAKgcAKwcALAcALQADBwAtBwAuAQAwAAAAAgAxAAEAMgAAAAIAMw==",
}

# Every identifier real AWS currently accepts for CreateFunction (java8 itself, the first java
# identifier, is excluded: it is deprecated with function creation blocked), paired with the
# java.specification.version its own JVM reports and an alternating architecture -- interpreted
# JVM bytecode runs unchanged on either, so the matrix spends its 8 slots spreading both axes.
IDENTIFIERS = [
    ("java8.al2", "1.8", "x86_64"),
    ("java8.al2023", "1.8", "arm64"),
    ("java11", "11", "x86_64"),
    ("java11.al2023", "11", "arm64"),
    ("java17", "17", "x86_64"),
    ("java17.al2023", "17", "arm64"),
    ("java21", "21", "x86_64"),
    ("java25", "25", "arm64"),
]

# The thrown frame: both classes are the SAME bytecode under every identifier above, so the
# LineNumberTable entry is pinned exactly rather than matched by a pattern.
THROW_FRAME = "probe.Matrix.mainHandler(Matrix.java:11)"


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
    # The role's invoke-time AssumeRole propagates on its own schedule, separate from the one
    # CreateFunction already waited through, so the same bounded retry applies here too.
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
    return resp.get("FunctionError"), json.loads(raw), resp["ResponseMetadata"]["RequestId"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """One compiled class tree, deployed under every java* identifier CreateFunction currently
    accepts (an Architecture rotated across them), reports an identical POJO-bound result, Context
    and unchecked-exception shape, and a java.specification.version matching its own identifier.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/java-context.html
    """
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _execution_role(ctx)
    zip_bytes = _deployment_zip()

    names = {identifier: ctx.unique_name(f"sim2real-behav-javafam-{i}-")
             for i, (identifier, _, _) in enumerate(IDENTIFIERS)}
    for fn in names.values():
        ctx.on_cleanup(lambda fn=fn: _reap_log_group(logs, f"/aws/lambda/{fn}"))
        ctx.on_cleanup(_teardown(lambda fn=fn: lam.delete_function(FunctionName=fn),
                                 "ResourceNotFoundException"))

    def _create_one(identifier, _spec, arch):
        fn = names[identifier]
        _create(lam, dict(
            FunctionName=fn, Runtime=identifier, Handler="probe.Matrix::mainHandler",
            Role=role_arn, Code={"ZipFile": zip_bytes}, MemorySize=512, Timeout=20,
            Architectures=[arch], Tags={"sim2real": CHECK},
        ))
        return fn

    with ThreadPoolExecutor(max_workers=len(IDENTIFIERS)) as pool:
        created = list(pool.map(lambda t: _create_one(*t), IDENTIFIERS))

    with ThreadPoolExecutor(max_workers=len(IDENTIFIERS)) as pool:
        list(pool.map(lambda fn: _wait_active(lam, fn), created))

    for identifier, expect_spec, expect_arch in IDENTIFIERS:
        fn = names[identifier]
        cfg = lam.get_function_configuration(FunctionName=fn)
        assert cfg["Runtime"] == identifier, (
            f"{fn}: GetFunctionConfiguration reported Runtime={cfg['Runtime']!r}, expected "
            f"the CreateFunction identifier {identifier!r}")
        assert cfg["Architectures"] == [expect_arch], (
            f"{fn}: Architectures {cfg['Architectures']!r} != requested [{expect_arch!r}]")

        err, body, req_id = _invoke(lam, fn, {"mode": "ok", "n": 3, "items": ["a", "b"]})
        assert err is None, f"{fn} ({identifier}) invoke failed: FunctionError={err!r} body={body!r}"
        assert body["javaSpecVersion"] == expect_spec, (
            f"{fn}: created with Runtime={identifier!r} but java.specification.version was "
            f"{body['javaSpecVersion']!r}, expected {expect_spec!r}")
        assert body["nPlusOne"] == 4 and body["items"] == ["a", "b"] and body["itemCount"] == 2, (
            f"{fn} ({identifier}): POJO binding gave {body!r}")
        assert body["functionName"] == fn, f"{fn}: getFunctionName() returned {body['functionName']!r}"
        assert body["awsRequestId"] == req_id, (
            f"{fn}: getAwsRequestId() {body['awsRequestId']!r} != Invoke response id {req_id!r}")
        assert 0 < body["remainingMs"] <= 20000, (
            f"{fn}: getRemainingTimeInMillis() {body['remainingMs']!r} outside (0, 20000]")
        assert body["memLimitMb"] == 512, f"{fn}: getMemoryLimitInMB() {body['memLimitMb']!r} != 512"

        terr, tbody, _ = _invoke(lam, fn, {"mode": "throw"})
        assert terr == "Unhandled", f"{fn} ({identifier}): throw path FunctionError={terr!r}"
        assert tbody.get("errorType") == "java.lang.IllegalStateException", (
            f"{fn} ({identifier}): errorType {tbody.get('errorType')!r}")
        assert tbody.get("errorMessage") == "probe-matrix-failure", (
            f"{fn} ({identifier}): errorMessage {tbody.get('errorMessage')!r}")
        trace = tbody.get("stackTrace") or []
        assert trace and trace[0] == THROW_FRAME, (
            f"{fn} ({identifier}): stackTrace[0] {trace[:1]!r} != {THROW_FRAME!r} -- the SAME "
            f"class file is deployed under every identifier, so the customer-code frame must "
            f"match byte for byte regardless of which JVM ran it (the frames below it are the "
            f"reflective dispatch each JDK major version ships and are not asserted here)")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
