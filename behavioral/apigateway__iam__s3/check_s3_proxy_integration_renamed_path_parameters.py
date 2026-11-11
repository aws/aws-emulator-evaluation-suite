"""s3-proxy-integration-renamed-path-parameters."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-proxy-integration-renamed-path-parameters"
GROUP = "service-integration"
SERVICES = ["apigateway", "iam", "s3"]

_THROTTLED = ("TooManyRequestsException", "Too Many Requests")
_TAGS = {"sim2real": CHECK}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GET /{folder}/{item} method whose S3 integration renames method.request.path.folder
    and .item onto integration.request.path.bucket and .object retrieves the object the
    URL's two segments select, and a nonexistent item in a valid bucket surfaces S3's 404."""
    bucket1 = _create_bucket(ctx)
    bucket2 = _create_bucket(ctx)
    s3 = ctx.client("s3")

    # Same item name in both buckets, different content: distinguishes which BUCKET was used.
    s3.put_object(Bucket=bucket1, Key="alpha.txt", Body=b"bucket-one-alpha", ContentType="text/plain")
    s3.put_object(Bucket=bucket2, Key="alpha.txt", Body=b"bucket-two-alpha", ContentType="text/plain")
    # A second item in bucket1, different content: distinguishes which ITEM was used.
    s3.put_object(Bucket=bucket1, Key="beta.txt", Body=b"bucket-one-beta", ContentType="text/plain")

    role_arn = _create_apigw_s3_role(ctx, [bucket1, bucket2])
    api_id, stage = _build_s3_proxy_api(ctx, role_arn)

    # ---- folder (bucket1) + item=alpha.txt -------------------------------------------------
    status, body = _poll_get(ctx, api_id, stage, bucket1, "alpha.txt")
    assert status == 200, f"expected 200 for {bucket1}/alpha.txt, got {status} body={body!r}"
    assert body == b"bucket-one-alpha", f"expected bucket1's alpha.txt body, got {body!r}"

    # ---- same item name, DIFFERENT folder (bucket2): proves folder -> integration bucket ----
    status, body = _poll_get(ctx, api_id, stage, bucket2, "alpha.txt")
    assert status == 200, f"expected 200 for {bucket2}/alpha.txt, got {status} body={body!r}"
    assert body == b"bucket-two-alpha", (
        f"expected bucket2's alpha.txt body (folder must select the bucket), got {body!r}"
    )

    # ---- same folder (bucket1), DIFFERENT item: proves item -> integration object ----------
    status, body = _poll_get(ctx, api_id, stage, bucket1, "beta.txt")
    assert status == 200, f"expected 200 for {bucket1}/beta.txt, got {status} body={body!r}"
    assert body == b"bucket-one-beta", (
        f"expected bucket1's beta.txt body (item must select the object), got {body!r}"
    )

    # ---- negative: a valid folder (bucket1) with an item that was never put surfaces S3's
    # own NoSuchKey through the integration, rather than a fixed 200. ----
    status, body = _poll_get(ctx, api_id, stage, bucket1, "missing.txt", expect_status=404)
    assert status == 404, f"expected 404 for a nonexistent item, got {status} body={body!r}"
    error = _s3_error(body)
    assert error == {
        "Code": "NoSuchKey", "Message": "The specified key does not exist.", "Key": "missing.txt",
    }, f"expected S3's exact NoSuchKey error for missing.txt, got {error!r} from {body!r}"


def _s3_error(body: bytes) -> dict:
    """An S3 XML error body's fields, without the per-request RequestId and HostId."""
    root = ET.fromstring(body)
    assert root.tag == "Error", f"expected an S3 <Error> document, got <{root.tag}>: {body!r}"
    return {child.tag: child.text for child in root if child.tag not in ("RequestId", "HostId")}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-apigw-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda b=bucket: _empty_and_delete_bucket(ctx, b))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _TAGS.items()]}
    )
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


def _create_apigw_s3_role(ctx, buckets: list[str]) -> str:
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
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda rn=role_name: _delete_role(ctx, rn))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": [f"arn:aws:s3:::{b}/*" for b in buckets],
            },
            {
                # Without ListBucket, GetObject on a missing key answers 403 AccessDenied
                # (S3 hides whether the key exists) instead of the 404 NoSuchKey this check
                # exercises.
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": [f"arn:aws:s3:::{b}" for b in buckets],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    return role_arn


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


def _delete_rest_api_quota_aware(apigw, api_id: str, *, budget_s: float = 320.0) -> None:
    """DeleteRestApi is quota'd to one call every 30 s per account and other tests may be
    deleting APIs concurrently; retry only the throttle across that window."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _THROTTLED or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _build_s3_proxy_api(ctx, role_arn: str) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    # The stage proxies S3 objects through a role, so only the runner's egress may invoke it.
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": "execute-api:/*",
            "Condition": {"IpAddress": {"aws:SourceIp": ctx.ingress_cidrs()}},
        }],
    }
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-s3-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=_TAGS,
        policy=json.dumps(policy),
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda aid=api_id: _delete_rest_api_quota_aware(apigw, aid))

    resources = apigw.get_resources(restApiId=api_id)
    root_id = [r["id"] for r in resources["items"] if r["path"] == "/"][0]
    folder_resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="{folder}")["id"]
    item_resource = apigw.create_resource(
        restApiId=api_id, parentId=folder_resource, pathPart="{item}"
    )["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=item_resource,
        httpMethod="GET",
        authorizationType="NONE",
        requestParameters={
            "method.request.path.folder": True,
            "method.request.path.item": True,
        },
    )
    # The integration's path parameter NAMES (bucket, object) differ from the method's
    # (folder, item); requestParameters is what renames one onto the other.
    uri = f"arn:aws:apigateway:{ctx.region}:s3:path/{{bucket}}/{{object}}"
    apigw.put_integration(
        restApiId=api_id,
        resourceId=item_resource,
        httpMethod="GET",
        type="AWS",
        integrationHttpMethod="GET",
        uri=uri,
        credentials=role_arn,
        passthroughBehavior="WHEN_NO_MATCH",
        requestParameters={
            "integration.request.path.bucket": "method.request.path.folder",
            "integration.request.path.object": "method.request.path.item",
        },
    )
    apigw.put_method_response(restApiId=api_id, resourceId=item_resource, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=item_resource, httpMethod="GET", statusCode="200",
        selectionPattern="2\\d{2}",
    )
    apigw.put_method_response(restApiId=api_id, resourceId=item_resource, httpMethod="GET", statusCode="404")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=item_resource, httpMethod="GET", statusCode="404",
        selectionPattern="4\\d{2}",
    )
    stage = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    return api_id, stage


def _http_get(url: str, verify=True):
    """GET ``url`` verifying the server with ``ctx.http_verify`` (True, or a CA bundle path)."""
    context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, method="GET"), timeout=15, context=context
        ) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError:
        return None, b""


def _poll_get(ctx, api_id: str, stage: str, folder: str, item: str, expect_status=200,
              timeout_s=120.0, interval_s=4.0):
    url = f"{ctx.rest_api_url(api_id, stage)}/{folder}/{item}"
    deadline = time.monotonic() + timeout_s
    last = (None, b"")
    while time.monotonic() < deadline:
        last = _http_get(url, verify=ctx.http_verify)
        if last[0] == expect_status:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
