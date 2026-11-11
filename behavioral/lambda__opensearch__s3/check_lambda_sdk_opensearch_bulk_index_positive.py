"""lambda-sdk-opensearch-bulk-index-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-opensearch-bulk-index-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "opensearch", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Lambda sends a signed _bulk request and every document becomes searchable."""
    account = _account_id(ctx)
    domain_name = _domain_name(ctx)
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{domain_name}"
    resource = f"{domain_arn}/*"

    role = _create_lambda_role(ctx, [{"Effect": "Allow", "Action": "es:ESHttp*", "Resource": resource}])
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": role["arn"]}, "Action": "es:ESHttp*", "Resource": resource}
        ],
    }
    domain = _create_domain(ctx, domain_name, access_policy)
    fn = _create_lambda_function(ctx, role["arn"])
    endpoint = ctx.endpoint_url(domain["endpoint"])
    index = "sim2real-bulk"

    docs = [{"sku": f"sku-{i}", "price": i * 10} for i in range(5)]
    lines = []
    for i, doc in enumerate(docs, start=1):
        lines.append(json.dumps({"index": {"_index": index, "_id": str(i)}}))
        lines.append(json.dumps(doc))
    ndjson = "\n".join(lines) + "\n"

    bulk = _invoke(
        ctx, fn, {"endpoint": endpoint, "method": "POST", "path": "/_bulk?refresh=true", "raw_body": ndjson}
    )
    assert bulk["statusCode"] == 200, bulk
    bulk_body = json.loads(bulk["body"])
    assert bulk_body["errors"] is False, bulk_body
    assert len(bulk_body["items"]) == 5, bulk_body

    search = _invoke(
        ctx,
        fn,
        {
            "endpoint": endpoint,
            "method": "GET",
            "path": f"/{index}/_search",
            "body": {"query": {"match_all": {}}, "size": 10},
        },
    )
    assert search["statusCode"] == 200, search
    hits = json.loads(search["body"])["hits"]
    assert hits["total"]["value"] == 5, hits
    skus = sorted(h["_source"]["sku"] for h in hits["hits"])
    assert skus == sorted(d["sku"] for d in docs), skus


# ===== helpers =====

_LAMBDA_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}

_LAMBDA_CODE = """
import json
import os
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


def handler(event, context):
    region = os.environ["AWS_REGION"]
    endpoint = event["endpoint"].rstrip("/")
    path = event.get("path", "/")
    method = event.get("method", "GET")
    body = event.get("body")
    raw_body = event.get("raw_body")
    if raw_body is not None:
        data = raw_body.encode("utf-8")
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
    else:
        data = b""
    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()
    url = endpoint + path
    headers = {"Content-Type": "application/json"} if data else {}
    signed = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(creds, "es", region).add_auth(signed)
    signed_headers = dict(signed.headers.items())
    http_req = urllib.request.Request(url, data=data if data else None, headers=signed_headers, method=method)
    try:
        with urllib.request.urlopen(http_req, timeout=25) as resp:
            return {"statusCode": resp.status, "body": resp.read().decode("utf-8")}
    except urllib.error.HTTPError as exc:
        return {"statusCode": exc.code, "body": exc.read().decode("utf-8")}
"""


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _domain_name(ctx) -> str:
    name = ctx.unique_name("sim2real-osx-").lower()
    name = "".join(c for c in name if c.isalnum() or c == "-").strip("-")
    return name[:28]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _create_domain(ctx, name: str, access_policy: dict) -> dict:
    client = ctx.client("opensearch")
    kwargs = dict(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(access_policy),
        TagList=[{"Key": "sim2real", "Value": name}],
    )
    # The access policy references an IAM role that was just created; OpenSearch's
    # policy-principal validation can lag IAM propagation, so retry on that specific
    # failure rather than the role's own permissions.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            client.create_domain(**kwargs)
            break
        except client.exceptions.InvalidTypeException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_domain(DomainName=name)))
    endpoint = _wait_for_domain_active(ctx, name, timeout_s=1800.0, interval_s=30.0)
    return {"name": name, "endpoint": endpoint}


def _wait_for_domain_active(ctx, name: str, timeout_s: float = 1800.0, interval_s: float = 30.0) -> str:
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if not status.get("Processing", True) and status.get("Endpoint"):
            return status["Endpoint"]
        time.sleep(interval_s)
    raise AssertionError(f"opensearch domain {name} did not become active within {timeout_s}s")


def _create_lambda_role(ctx, es_statements: list[dict]) -> dict:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-osrole-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["Role"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=name)))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=basic_policy_arn)))
    if es_statements:
        doc = {"Version": "2012-10-17", "Statement": es_statements}
        iam.put_role_policy(RoleName=name, PolicyName="es-access", PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=name, PolicyName="es-access")))
    return {"name": name, "arn": role["Arn"]}


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-osfn-")
    code = _zip_code(_LAMBDA_CODE)
    last_err = None
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code},
                Timeout=30,
                MemorySize=256,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"create_function never succeeded (role propagation?): {last_err}"
                ) from exc
            time.sleep(2.0)
    ctx.on_cleanup(lambda: _safe(lambda: lam.delete_function(FunctionName=name)))
    _wait_for_function_active(ctx, name)
    return name


def _wait_for_function_active(ctx, name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("State") == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"lambda function {name} never became Active")


def _invoke(ctx, function_name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
    raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed: {raw!r}")
    return json.loads(raw)


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
