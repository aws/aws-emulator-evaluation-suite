"""apigw-s3-direct-integration-getobject-positive."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-s3-direct-integration-getobject-positive"
GROUP = "event-propagation"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """API Gateway AWS-service proxy integration to S3 GetObject streams the real
    object body through the API response (not a stubbed/echoed passthrough)."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "object.txt"
    content = f"hello-from-s3-{ctx.unique_name('payload-')}"
    s3.put_object(Bucket=bucket, Key=key, Body=content.encode("utf-8"))

    _role_name, role_arn = _create_role(
        ctx,
        principals="apigateway.amazonaws.com",
        policy_statements=[
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/{key}"}
        ],
    )

    api_id, root_id = _create_rest_api(ctx)
    resource_id = _add_resource(ctx, api_id, root_id, "object")
    uri = f"arn:aws:apigateway:{ctx.region}:s3:path/{bucket}/{key}"
    _wire_s3_integration(ctx, api_id, resource_id, "GET", uri, role_arn)
    invoke_url = _deploy(ctx, api_id)

    result = _poll_until(
        lambda: _invoke(f"{invoke_url}/object", "GET", verify=ctx.http_verify),
        lambda r: r[0] == 200 and r[1] == content,
        timeout_s=90.0,
        interval_s=3.0,
    )
    status, body = result
    assert status == 200, f"expected 200, got {status}: {body!r}"
    assert body == content, f"expected object body {content!r}, got {body!r}"


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _invoke(url, method="GET", data=None, headers=None, verify=True):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_https_context(verify)) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError:
        return None, ""


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bkt-")
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=bucket)
            objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_role(ctx, principals, policy_statements=None, policy_name="inline-policy"):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principals}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup():
        try:
            for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    if policy_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
    return role_name, role_arn


def _create_rest_api(ctx):
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"), tags={"simparity-check": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    return api_id, root_id


def _add_resource(ctx, api_id, parent_id, path_part):
    apigw = ctx.client("apigateway")
    res = apigw.create_resource(restApiId=api_id, parentId=parent_id, pathPart=path_part)
    return res["id"]


def _wire_s3_integration(ctx, api_id, resource_id, http_method, s3_uri, role_arn, integration_http_method=None):
    apigw = ctx.client("apigateway")
    integration_http_method = integration_http_method or http_method
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, authorizationType="NONE")
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="AWS",
        integrationHttpMethod=integration_http_method,
        uri=s3_uri,
        credentials=role_arn,
    )
    apigw.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method, statusCode="200")


def _deploy(ctx, api_id, stage="test"):
    apigw = ctx.client("apigateway")
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    return ctx.rest_api_url(api_id, stage)


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
