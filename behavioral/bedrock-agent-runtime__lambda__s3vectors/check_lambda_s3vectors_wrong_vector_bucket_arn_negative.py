"""lambda-s3vectors-wrong-vector-bucket-arn-negative."""
from __future__ import annotations

import importlib
import io
import json
import os
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "lambda-s3vectors-wrong-vector-bucket-arn-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutVectors from a Lambda with an indexArn pointing at an unrelated bucket gets NotFoundException
    with the exact message and writes to neither bucket, while the correct indexArn lands the vector."""
    intended = _create_bucket_and_index(ctx, dimension=4)
    decoy = _create_empty_bucket(ctx)

    role_arn = _create_role(ctx, [{"Effect": "Allow", "Action": "s3vectors:*", "Resource": "*"}])
    fn_name = _create_dispatcher_lambda(ctx, role_arn)

    mismatched_arn = intended["index_arn"].replace(
        f"bucket/{intended['bucket_name']}/", f"bucket/{decoy['bucket_name']}/"
    )
    assert mismatched_arn != intended["index_arn"], (
        f"expected the bucket-swapped ARN to differ from the intended one, "
        f"got identical ARN {mismatched_arn!r}"
    )

    failed_body = _invoke_ok_or_failed(
        ctx,
        fn_name,
        "put_vectors",
        {"indexArn": mismatched_arn, "vectors": [{"key": "misrouted", "data": {"float32": [1.0, 2.0, 3.0, 4.0]}}]},
    )
    assert failed_body["ok"] is False, (
        f"expected PutVectors against the decoy-bucket ARN to fail, got ok=True: {failed_body}"
    )
    assert failed_body["code"] == "NotFoundException", (
        f"expected NotFoundException for the bucket-swapped indexArn, got code={failed_body['code']!r}"
    )
    expected_message = "The specified index could not be found"
    assert failed_body["error_message"] == expected_message, (
        f"expected {expected_message!r}, got {failed_body['error_message']!r}"
    )

    # (b) the effect is absent from BOTH buckets: nothing was written to the intended
    # bucket's real index, and the decoy bucket never gained an index at all.
    s3v = ctx.client("s3vectors")
    survivors = s3v.get_vectors(
        vectorBucketName=intended["bucket_name"],
        indexName=intended["index_name"],
        keys=["misrouted"],
        returnData=True,
    )["vectors"]
    assert survivors == [], (
        f"expected no vectors written to the intended index after the misrouted call, got {survivors}"
    )
    decoy_indexes = s3v.list_indexes(vectorBucketName=decoy["bucket_name"])["indexes"]
    assert decoy_indexes == [], (
        f"expected the decoy bucket to have gained no index, got {decoy_indexes}"
    )

    # (c) positive control: the correct indexArn for the intended bucket works.
    control_body = _invoke_ok(
        ctx,
        fn_name,
        "put_vectors",
        {"indexArn": intended["index_arn"], "vectors": [{"key": "routed", "data": {"float32": [1.0, 2.0, 3.0, 4.0]}}]},
    )
    assert control_body["ok"] is True, (
        f"expected PutVectors with the correct indexArn to succeed, got {control_body}"
    )
    landed = s3v.get_vectors(
        vectorBucketName=intended["bucket_name"],
        indexName=intended["index_name"],
        keys=["routed"],
        returnData=True,
    )["vectors"]
    assert len(landed) == 1, f"expected exactly 1 vector landed via the control call, got {len(landed)}: {landed}"
    assert landed[0]["key"] == "routed", f"expected landed vector key 'routed', got {landed[0]['key']!r}"


_HANDLER_CODE = '''
import boto3
import json


def handler(event, context):
    client = boto3.client("s3vectors")
    action = event["action"]
    params = event.get("params", {})
    method = getattr(client, action)
    try:
        result = method(**params)
        result.pop("ResponseMetadata", None)
        safe = json.loads(json.dumps(result, default=str))
        return {"ok": True, "result": safe}
    except Exception as exc:
        resp = getattr(exc, "response", None)
        code = resp["Error"]["Code"] if resp and "Error" in resp else type(exc).__name__
        error_message = resp["Error"].get("Message", "") if resp and "Error" in resp else str(exc)
        return {"ok": False, "code": code, "message": str(exc), "error_message": error_message}
'''

_ALLOWED_BOTOCORE_DATA_SERVICES = {"s3vectors"}
_BUNDLE_MODULES = ("boto3", "botocore")


def _add_module_to_zip(zf: zipfile.ZipFile, module_name: str) -> None:
    mod = importlib.import_module(module_name)
    mod_path = getattr(mod, "__path__", None)
    if not mod_path:
        zf.write(mod.__file__, arcname=os.path.basename(mod.__file__))
        return
    pkg_dir = mod_path[0]
    root_dir = os.path.dirname(pkg_dir)
    data_dir = os.path.join(pkg_dir, "data")
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        if dirpath == data_dir:
            dirnames[:] = [d for d in dirnames if d in _ALLOWED_BOTOCORE_DATA_SERVICES]
        for fname in filenames:
            if fname.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(dirpath, fname)
            arc = os.path.relpath(full, root_dir)
            zf.write(full, arcname=arc)


def _build_deployment_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER_CODE)
        for name in _BUNDLE_MODULES:
            _add_module_to_zip(zf, name)
    return buf.getvalue()


def _create_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-s3v-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=name, PolicyName="inline-s3vectors", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline-s3vectors"))
    return role_arn


def _create_dispatcher_lambda(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-s3v-fn-")
    code = _build_deployment_zip()
    deadline = time.monotonic() + 60.0
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=30,
                MemorySize=256,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    deadline = time.monotonic() + 60.0
    while True:
        state = lam.get_function(FunctionName=name)["Configuration"]["State"]
        if state == "Active":
            break
        if state == "Failed" or time.monotonic() > deadline:
            raise AssertionError(f"lambda function never became Active (state={state})")
        time.sleep(2)
    return name


def _invoke(ctx, function_name: str, action: str, params: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps({"action": action, "params": params}).encode("utf-8"),
    )
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised: {resp['Payload'].read().decode()}")
    return json.loads(resp["Payload"].read())


def _invoke_ok(ctx, function_name: str, action: str, params: dict[str, Any], timeout_s: float = 45.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        body = _invoke(ctx, function_name, action, params)
        if body.get("ok"):
            return body
        last = body
        if body.get("code") not in ("AccessDeniedException", "ServiceUnavailableException", "InternalServerException"):
            raise AssertionError(f"unexpected failure for {action}: {body}")
        time.sleep(2)
    raise AssertionError(f"{action} never succeeded, last={last}")


def _invoke_ok_or_failed(ctx, function_name: str, action: str, params: dict[str, Any], timeout_s: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        body = _invoke(ctx, function_name, action, params)
        if body.get("ok") is False and body.get("code") == "NotFoundException":
            return body
        last = body
        if body.get("code") not in ("ServiceUnavailableException", "InternalServerException", "AccessDeniedException"):
            return body
        time.sleep(2)
    raise AssertionError(f"{action} never reached a stable outcome, last={last}")


def _create_bucket_and_index(ctx, dimension: int, distance_metric: str = "cosine") -> dict[str, str]:
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-bkt-")
    bucket_arn = s3v.create_vector_bucket(
        vectorBucketName=bucket_name, tags={"sim2real": CHECK}
    )["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    index_name = ctx.unique_name("sim2real-s3v-idx-")
    index_arn = s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric=distance_metric,
        tags={"sim2real": CHECK},
    )["indexArn"]
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    return {
        "bucket_name": bucket_name,
        "bucket_arn": bucket_arn,
        "index_name": index_name,
        "index_arn": index_arn,
    }


def _create_empty_bucket(ctx) -> dict[str, str]:
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-bkt-")
    bucket_arn = s3v.create_vector_bucket(
        vectorBucketName=bucket_name, tags={"sim2real": CHECK}
    )["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    return {"bucket_name": bucket_name, "bucket_arn": bucket_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
