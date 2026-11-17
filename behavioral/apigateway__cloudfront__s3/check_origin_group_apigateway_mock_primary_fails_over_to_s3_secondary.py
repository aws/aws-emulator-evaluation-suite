"""origin-group-apigateway-mock-primary-fails-over-to-s3-secondary."""
from __future__ import annotations

import json
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "origin-group-apigateway-mock-primary-fails-over-to-s3-secondary"
GROUP = "origin-group-failover"
SERVICES = ["apigateway", "cloudfront", "s3"]

#: Managed-CachingOptimized -- a stable AWS-managed cache policy id (reference data), used so a
#: cached failover answer survives until the check invalidates it on purpose.
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An origin group fails a path over from a key-gated MOCK REST API primary answering 503 to
    a private S3 secondary, serves a path the primary answers 200 for unchanged, and reverts to
    the primary once it is reconfigured to 200 and the cached path is invalidated.
    """
    apigw = ctx.client("apigateway")
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    bucket = ctx.unique_name("sim2real-behav-cfog-sec-").lower()
    secondary_key = "f/obj.txt"
    secondary_body = b"sim2real-cfog-served-by-secondary-s3-origin"
    _create_private_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=secondary_key, Body=secondary_body, ContentType="text/plain")

    api_id, stage = _create_mock_api(ctx, apigw)
    api_key = _require_api_key(ctx, apigw, api_id, stage)
    primary_domain = f"{api_id}.execute-api.{ctx.region}.amazonaws.com"

    ok_body = {"origin": "primary-mock", "answered": "ok"}
    recovered_body = {"origin": "primary-mock", "answered": "f-recovered"}

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-cfog-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-cfog-cr-"),
        "Comment": "sim2real origin group failover across apigateway and s3",
        "Enabled": True,
        "Origins": {"Quantity": 2, "Items": [
            {
                "Id": "primary-origin",
                "DomainName": primary_domain,
                "OriginPath": f"/{stage}",
                "CustomHeaders": {"Quantity": 1, "Items": [
                    {"HeaderName": "x-api-key", "HeaderValue": api_key}]},
                "CustomOriginConfig": {
                    "HTTPPort": 80,
                    "HTTPSPort": 443,
                    "OriginProtocolPolicy": "https-only",
                    "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    "OriginReadTimeout": 30,
                    "OriginKeepaliveTimeout": 5,
                },
            },
            {
                "Id": "secondary-origin",
                "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                "S3OriginConfig": {"OriginAccessIdentity": ""},
                "OriginAccessControlId": oac_id,
            },
        ]},
        "OriginGroups": {"Quantity": 1, "Items": [{
            "Id": "failover-group",
            "FailoverCriteria": {"StatusCodes": {"Quantity": 1, "Items": [503]}},
            "Members": {"Quantity": 2, "Items": [
                {"OriginId": "primary-origin"},
                {"OriginId": "secondary-origin"},
            ]},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "failover-group",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before the bucket policy so a failing create still tears down the distribution.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    dist_arn = dist["ARN"]

    _allow_cloudfront_oac(s3, bucket, dist_arn, dist_arn.split(":")[1])

    _wait_distribution_deployed(cf, dist_id)

    session = requests.Session()
    edge, route = ctx.endpoint_route(dist["DomainName"])
    session.headers.update(route)

    served_ok = _poll_get_json(session, f"{edge}/ok", verify=ctx.http_verify)
    assert served_ok == ok_body, (
        f"a path the primary answers 200 for must be served by the primary unchanged: "
        f"expected {ok_body!r}, got {served_ok!r}"
    )

    served_failover = _poll_get(
        session, f"{edge}/f/obj.txt",
        lambda r: r.status_code == 200 and bool(r.content),
        verify=ctx.http_verify,
    )
    assert served_failover.content == secondary_body, (
        f"the primary answers 503 for /f/obj.txt, so the origin group must fail over to the "
        f"secondary's exact bytes: expected {secondary_body!r}, got "
        f"{served_failover.content[:120]!r}"
    )

    f_resource_id = _f_resource_id(apigw, api_id)
    _reconfigure_mock_to_200(apigw, api_id, f_resource_id, recovered_body)
    apigw.create_deployment(restApiId=api_id, stageName=stage)

    # An independent read at the stage's own regional endpoint, bypassing CloudFront entirely:
    # the redeployed stage must already answer 200 before the distribution is invalidated, or
    # CloudFront can refetch during the redeploy's own propagation, fail over again and re-cache
    # the secondary's answer under an invalidation that was already spent.
    direct_session = requests.Session()
    direct_session.headers.update({"x-api-key": api_key})
    direct_url = f"{ctx.rest_api_url(api_id, stage)}/f/obj.txt"
    direct_probe = _poll_get(direct_session, direct_url, lambda r: r.status_code == 200,
                              timeout_s=180.0, verify=ctx.http_verify)
    assert json.loads(direct_probe.content) == recovered_body, (
        f"the reconfigured mock must answer the recovered body directly, before anything is "
        f"asserted about what the distribution serves: got {direct_probe.content[:200]!r}"
    )
    # The same direct request without the key: the stage serves nobody but the distribution.
    unkeyed = _poll_until(
        lambda: _get_or_error(requests, direct_url, verify=ctx.http_verify),
        lambda r: isinstance(r, requests.Response), timeout_s=60.0,
        description=f"any HTTP answer from {direct_url}",
    )
    assert (unkeyed.status_code, json.loads(unkeyed.content)) == (403, {"message": "Forbidden"}), (
        f"a direct request carrying no API key must be refused with 403 Forbidden: got "
        f"{unkeyed.status_code} {unkeyed.content[:200]!r}"
    )

    invalidation_id = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/f/obj.txt"]},
            "CallerReference": ctx.unique_name("sim2real-cfog-inval-"),
        },
    )["Invalidation"]["Id"]
    _wait_invalidation_completed(cf, dist_id, invalidation_id)

    # Invalidation Completed means the control plane processed the request; edge locations finish
    # dropping the cached failover answer over the following minutes, so the budget is generous.
    recovered = _poll_get_json(session, f"{edge}/f/obj.txt", timeout_s=1200.0, interval_s=10.0,
                                verify=ctx.http_verify)
    assert recovered == recovered_body, (
        f"after the mock answers 200 for /f/* and the cached path is invalidated, /f/obj.txt "
        f"must come from the primary again: expected {recovered_body!r}, got {recovered!r}"
    )


# ===== origin-group helpers =====

def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _get_or_error(session, url, *, verify):
    """One GET; a transport error (DNS, connect, TLS, timeout) is returned, so a poll retries it."""
    try:
        return session.get(url, timeout=15, verify=verify)
    except requests.RequestException as exc:
        return exc


def _poll_get(session, url, predicate, *, timeout_s=180.0, interval_s=5.0, verify):
    """Poll until a response satisfies ``predicate``; a transport error is retried."""
    def probe():
        return _get_or_error(session, url, verify=verify)

    return _poll_until(probe, lambda r: isinstance(r, requests.Response) and predicate(r),
                        timeout_s=timeout_s, interval_s=interval_s,
                        description=f"the expected answer from {url}")


def _poll_get_json(session, url, *, timeout_s=180.0, interval_s=5.0, verify):
    """Poll until a 200 arrives whose body parses as JSON.

    Right after a distribution first reports Deployed, a POP that has not yet synced the config
    can answer with a transient empty or non-JSON 200; retrying past that is not retrying on the
    asserted value itself, which the final parsed body still is.
    """
    holder: dict = {}

    def probe():
        resp = _get_or_error(session, url, verify=verify)
        if not isinstance(resp, requests.Response):
            holder["status"], holder["content"] = None, repr(resp).encode()
            return None
        holder["status"] = resp.status_code
        holder["content"] = resp.content
        if resp.status_code != 200:
            return None
        try:
            holder["parsed"] = json.loads(resp.content)
        except ValueError:
            return None
        return resp

    try:
        _poll_until(probe, lambda r: r is not None, timeout_s=timeout_s, interval_s=interval_s,
                    description=f"a 200 with a JSON body from {url}")
    except AssertionError as exc:
        raise AssertionError(
            f"{exc}; last status {holder.get('status')!r}, body {holder.get('content', b'')[:200]!r}"
        ) from exc
    return holder["parsed"]


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=15.0) -> None:
    """A distribution takes several minutes to leave InProgress; the budget leaves wide margin."""
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda status: status == "Deployed",
        timeout_s=timeout_s, interval_s=interval_s,
        description=f"distribution {dist_id} to reach Deployed",
    )


def _wait_invalidation_completed(cf, dist_id, invalidation_id, *, timeout_s=600.0, interval_s=10.0) -> None:
    _poll_until(
        lambda: cf.get_invalidation(DistributionId=dist_id, Id=invalidation_id)["Invalidation"]["Status"],
        lambda status: status == "Completed",
        timeout_s=timeout_s, interval_s=interval_s,
        description=f"invalidation {invalidation_id} to reach Completed",
    )


def _disable_and_delete_distribution(cf, dist_id) -> None:
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_oac(cf, oac_id) -> None:
    etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _allow_cloudfront_oac(s3, bucket, dist_arn, partition) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipalReadOnly",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:{partition}:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))


def _create_private_bucket(ctx, s3, bucket) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    })


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


# ===== API Gateway MOCK primary helpers =====

def _require_api_key(ctx, apigw, api_id, stage) -> str:
    """An enabled API key in a usage plan covering ``stage``: every primary method requires it,
    so the stage answers 403 to any caller but the distribution, whose origin custom header
    carries the returned key value."""
    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-cfog-plan-"),
        apiStages=[{"apiId": api_id, "stage": stage}],
        throttle={"rateLimit": 10.0, "burstLimit": 5},
    )["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan(apigw, plan_id, api_id, stage))
    key = apigw.create_api_key(name=ctx.unique_name("sim2real-cfog-key-"), enabled=True)
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key["id"]))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key["id"], keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key["id"]))
    return key["value"]


def _delete_usage_plan(apigw, plan_id, api_id, stage) -> None:
    """A usage plan with an associated API stage cannot be deleted; detach it, then delete."""
    try:
        apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "remove", "path": "/apiStages", "value": f"{api_id}:{stage}"}],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    apigw.delete_usage_plan(usagePlanId=plan_id)


def _create_mock_api(ctx, apigw) -> tuple[str, str]:
    """A REGIONAL REST API with a MOCK /ok (200) and a MOCK /f/{proxy+} (503), deployed once."""
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-cfog-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")

    ok_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="ok")["id"]
    _put_mock_method(apigw, api_id, ok_id, 200, {"origin": "primary-mock", "answered": "ok"})

    f_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="f")["id"]
    proxy_id = apigw.create_resource(restApiId=api_id, parentId=f_id, pathPart="{proxy+}")["id"]
    _put_mock_method(apigw, api_id, proxy_id, 503, {"origin": "primary-mock", "answered": "failing"})

    stage = "live"
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    return api_id, stage


def _f_resource_id(apigw, api_id) -> str:
    items = apigw.get_resources(restApiId=api_id)["items"]
    return next(r["id"] for r in items if r["path"] == "/f/{proxy+}")


def _put_mock_method(apigw, api_id, resource_id, status_code, response_body) -> None:
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                     authorizationType="NONE", apiKeyRequired=True)
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": f'{{"statusCode": {status_code}}}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                               statusCode=str(status_code))
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode=str(status_code),
        responseTemplates={"application/json": json.dumps(response_body)},
    )


def _reconfigure_mock_to_200(apigw, api_id, resource_id, response_body) -> None:
    """Swap the /f/{proxy+} MOCK from its fixed 503 to a fixed 200: only one status may answer
    a MOCK integration at a time, so the 503 responses are removed before the 200 ones are added.
    """
    apigw.delete_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                                       statusCode="503")
    apigw.delete_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                                  statusCode="503")
    apigw.update_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        patchOperations=[{
            "op": "replace",
            "path": "/requestTemplates/application~1json",
            "value": '{"statusCode": 200}',
        }],
    )
    apigw.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": json.dumps(response_body)},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
