"""lambda-opensearchserverless-batch-get-collection-positive."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-opensearchserverless-batch-get-collection-positive"
GROUP = "sdk-call"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Lambda invokes BatchGetCollection and receives collection metadata including endpoint and status."""
    coll_name = _aoss_name(ctx, "sim2real-bg-", max_len=40)
    collection = _create_collection(ctx, coll_name)
    _wait_collection_active(ctx, collection["id"])

    role_arn, _ = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": "aoss:BatchGetCollection", "Resource": "*"}]
    )
    fn_name = _create_lambda_function(ctx, role_arn)

    result = _invoke_expect_ok(
        ctx,
        fn_name,
        {"mode": "api", "action": "batch_get_collection", "params": {"names": [coll_name]}},
    )
    assert result["ok"] is True, result
    details = result["result"]["collectionDetails"]
    assert len(details) == 1, details
    detail = details[0]
    assert detail["name"] == coll_name
    assert detail["id"] == collection["id"]
    assert detail["status"] == "ACTIVE"
    assert detail["collectionEndpoint"].startswith("https://")


IAM_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

LAMBDA_CODE = '''
import json
import os
import urllib.request
import urllib.error

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import Session


def handler(event, context):
    mode = event.get("mode", "api")
    if mode == "api":
        client = boto3.client("opensearchserverless")
        action = event["action"]
        params = event.get("params", {})
        try:
            method = getattr(client, action)
            resp = method(**params)
            resp.pop("ResponseMetadata", None)
            return {"ok": True, "result": resp}
        except Exception as exc:  # noqa: BLE001
            err = getattr(exc, "response", {}) or {}
            code = err.get("Error", {}).get("Code", type(exc).__name__)
            return {"ok": False, "error_code": code, "error_message": str(exc)}
    else:
        endpoint = event["endpoint"]
        http_method = event.get("method", "GET")
        path = event["path"]
        body = event.get("body")
        data = json.dumps(body).encode("utf-8") if body is not None else b""
        session = Session()
        credentials = session.get_credentials()
        region = os.environ["AWS_REGION"]
        url = "https://" + endpoint + path
        headers = {"Content-Type": "application/json"}
        request = AWSRequest(method=http_method, url=url, data=data, headers=headers)
        SigV4Auth(credentials, "aoss", region).add_auth(request)
        req = urllib.request.Request(
            url, data=data if data else None, headers=dict(request.headers.items()), method=http_method
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return {"ok": True, "status": resp.status, "body": resp.read().decode("utf-8")}
        except urllib.error.HTTPError as exc:
            return {"ok": False, "status": exc.code, "body": exc.read().decode("utf-8")}
'''


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _aoss_name(ctx: Any, prefix: str, max_len: int = 32) -> str:
    raw = ctx.unique_name(prefix).lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    if not raw or not raw[0].isalpha():
        raw = "s" + raw
    return raw[:max_len].rstrip("-")


def _create_lambda_role(ctx: Any, statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-aoss-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=IAM_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    def _cleanup_role() -> None:
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="aoss-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="aoss-access",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn, role_name


def _create_lambda_function(ctx: Any, role_arn: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-aoss-fn-")
    zip_bytes = _zip_code(LAMBDA_CODE)
    last_exc: Exception | None = None
    ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=256,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            if time.monotonic() >= deadline:
                raise AssertionError(f"lambda function never became creatable: {last_exc}") from exc
            time.sleep(2)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_lambda_active(ctx, fn_name)
    return fn_name


def _wait_lambda_active(ctx: Any, fn_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=fn_name)["Configuration"]["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError("lambda function entered Failed state")
        time.sleep(2)
    raise AssertionError("lambda function did not become Active in time")


def _invoke(ctx: Any, fn_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised an unhandled error: {body}")
    return body


def _invoke_expect_ok(
    ctx: Any, fn_name: str, payload: dict[str, Any], timeout_s: float = 60.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    result: dict[str, Any] = {}
    while time.monotonic() < deadline:
        result = _invoke(ctx, fn_name, payload)
        if result.get("ok"):
            return result
        if result.get("error_code") not in ("AccessDeniedException", "UnauthorizedOperation"):
            return result
        time.sleep(3)
    return result


def _create_collection(ctx: Any, name: str) -> dict[str, str]:
    client = ctx.client("opensearchserverless")
    resp = client.create_collection(
        name=name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    detail = resp["createCollectionDetail"]
    coll_id = detail["id"]
    ctx.on_cleanup(lambda: _delete_collection(ctx, coll_id))
    return {"id": coll_id, "arn": detail["arn"], "name": name}


def _delete_collection(ctx: Any, coll_id: str) -> None:
    client = ctx.client("opensearchserverless")
    try:
        client.delete_collection(id=coll_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_collection_active(
    ctx: Any, coll_id: str, timeout_s: float = 900.0, interval_s: float = 20.0
) -> dict[str, Any]:
    client = ctx.client("opensearchserverless")
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = client.batch_get_collection(ids=[coll_id])
        details = resp.get("collectionDetails", [])
        if details:
            last = details[0]
            status = last["status"]
            if status == "ACTIVE":
                return last
            if status == "FAILED":
                raise AssertionError(f"collection entered FAILED state: {last.get('failureMessage')}")
        time.sleep(interval_s)
    raise AssertionError(f"collection did not become ACTIVE within {timeout_s}s; last={last}")


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
