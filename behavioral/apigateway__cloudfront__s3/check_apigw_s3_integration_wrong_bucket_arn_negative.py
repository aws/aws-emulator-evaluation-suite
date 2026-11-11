"""apigw-s3-integration-wrong-bucket-arn-negative."""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "apigw-s3-integration-wrong-bucket-arn-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An S3 integration whose URI names the wrong bucket fails with NoSuchBucket and the intended bucket
    never receives the key, while a sibling method with the correct bucket writes the object."""
    s3 = ctx.client("s3")
    intended_bucket = _create_bucket(ctx)
    wrong_bucket = ctx.unique_name("sim2real-bkt-neverexisted-")  # deliberately never created
    key = "target.txt"
    wrong_content = f"should-never-land-{ctx.unique_name('payload-')}"
    right_content = f"should-land-{ctx.unique_name('payload-')}"

    # Broad PutObject permission on all buckets so the only possible failure
    # mode for the mismatched-ARN path is routing (bucket doesn't exist), not
    # an IAM permission gap.
    _role_name, role_arn = _create_role(
        ctx,
        principals="apigateway.amazonaws.com",
        policy_statements=[{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::*/*"}],
    )

    api_id, root_id = _create_rest_api(ctx)

    wrong_resource_id = _add_resource(ctx, api_id, root_id, "wrongput")
    wrong_uri = f"arn:aws:apigateway:{ctx.region}:s3:path/{wrong_bucket}/{key}"
    _wire_s3_integration(ctx, api_id, wrong_resource_id, "PUT", wrong_uri, role_arn)

    right_resource_id = _add_resource(ctx, api_id, root_id, "rightput")
    right_uri = f"arn:aws:apigateway:{ctx.region}:s3:path/{intended_bucket}/{key}"
    _wire_s3_integration(ctx, api_id, right_resource_id, "PUT", right_uri, role_arn)

    invoke_url = _deploy(ctx, api_id)

    status, body = _poll_until(
        lambda: _invoke(f"{invoke_url}/wrongput", "PUT", data=wrong_content.encode("utf-8"), verify=ctx.http_verify),
        lambda r: r[0] is not None and _s3_error_code(r[1]) is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert status is not None, "integration never became invokable"
    code = _s3_error_code(body)
    assert code == "NoSuchBucket", f"expected NoSuchBucket, got {code!r} (body={body!r})"

    exists = True
    try:
        s3.get_object(Bucket=intended_bucket, Key=key)
    except s3.exceptions.NoSuchKey:
        exists = False
    except Exception as e:  # pragma: no cover - defensive
        if _error_code(e) == "NoSuchKey":
            exists = False
        else:
            raise
    assert not exists, "intended bucket unexpectedly received the object via the mismatched ARN"

    # Positive control: the sibling method with the CORRECT bucket ARN succeeds.
    def _attempt_and_read():
        _invoke(f"{invoke_url}/rightput", "PUT", data=right_content.encode("utf-8"), verify=ctx.http_verify)
        return _get_object_body(s3, intended_bucket, key)

    written = _poll_until(_attempt_and_read, lambda v: v == right_content, timeout_s=90.0, interval_s=3.0)
    assert written == right_content, f"expected intended bucket to hold {right_content!r}, got {written!r}"


def _get_object_body(s3, bucket, key):
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
    except Exception:
        return None


def _error_code(exc):
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


def _s3_error_code(body):
    m = re.search(r"<Code>([^<]+)</Code>", body or "")
    return m.group(1) if m else None


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
    # us-east-1 is the one region where CreateBucketConfiguration.LocationConstraint
    # must be omitted entirely; passing it (even as "us-east-1") is rejected.
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"),
        tags={"sim2real": "true"},
    )
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
