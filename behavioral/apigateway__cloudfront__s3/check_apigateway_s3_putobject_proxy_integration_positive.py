"""apigateway-s3-putobject-proxy-integration-positive."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigateway-s3-putobject-proxy-integration-positive"
GROUP = "service-integration"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """API Gateway PUT method with S3 integration writes the request body into the bucket."""
    bucket = _create_bucket(ctx)
    key = ctx.unique_name("obj").replace("_", "-") + ".txt"
    body_payload = b"written through api gateway PUT -> s3 integration\n"

    _role_name, role_arn = _create_apigw_s3_role(ctx, bucket, key, "s3:PutObject")
    _api_id, invoke_url = _build_s3_literal_api(ctx, bucket, key, "PUT", role_arn)

    status, resp_body, _headers = _poll_until_status(
        invoke_url, "PUT", 200, data=body_payload, headers={"Content-Type": "text/plain"}, timeout_s=120, interval_s=4, verify=ctx.http_verify
    )
    assert status == 200, f"expected 200 from S3-proxied PUT, last status={status} body={resp_body!r}"

    s3 = ctx.client("s3")
    written = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert written == body_payload, f"object written via proxy PUT mismatch: got {written!r}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-apigw-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda b=bucket: _empty_and_delete_bucket(ctx, b))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_apigw_s3_role(ctx, bucket: str, key: str, action) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-apigw-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "apigateway.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda rn=role_name: _delete_role(ctx, rn))
    if action:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": action, "Resource": f"arn:aws:s3:::{bucket}/{key}"}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    return role_name, role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _build_s3_literal_api(ctx, bucket: str, key: str, http_method: str, role_arn: str) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-s3-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda aid=api_id: apigw.delete_rest_api(restApiId=aid))

    resources = apigw.get_resources(restApiId=api_id)
    root_id = [r["id"] for r in resources["items"] if r["path"] == "/"][0]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=key)
    resource_id = resource["id"]

    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE")
    uri = f"arn:aws:apigateway:{ctx.region}:s3:path/{bucket}/{key}"
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="AWS",
        integrationHttpMethod=http_method,
        uri=uri,
        credentials=role_arn,
        passthroughBehavior="WHEN_NO_MATCH",
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200"
    )
    apigw.create_deployment(restApiId=api_id, stageName="test")
    invoke_url = f"{ctx.rest_api_url(api_id, 'test')}/{key}"
    return api_id, invoke_url


def _http_request(url: str, method: str = "GET", data: bytes | None = None, headers: dict | None = None, verify=True):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_https_context(verify)) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers or {})
    except urllib.error.URLError:
        return None, b"", {}


def _poll_until_status(
    url: str,
    method: str,
    expected_status: int,
    data: bytes | None = None,
    headers: dict | None = None,
    timeout_s: float = 90.0,
    interval_s: float = 3.0,
    verify=True,
):
    deadline = time.monotonic() + timeout_s
    last = (None, b"", {})
    while time.monotonic() < deadline:
        last = _http_request(url, method=method, data=data, headers=headers, verify=verify)
        if last[0] == expected_status:
            return last
        time.sleep(interval_s)
    return last


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
