"""origin-access-control-signs-lambda-url-origin-and-direct-call-denied."""
from __future__ import annotations

import io
import json
import time
import urllib.parse
import zipfile

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "origin-access-control-signs-lambda-url-origin-and-direct-call-denied"
GROUP = "security"
SERVICES = ["cloudfront", "lambda"]

#: Prefix that classifies a failure as an unimplemented data plane.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: Managed CachingDisabled: every request must reach the origin, or the negative leg could be
#: answered out of the positive leg's cache entry.
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

#: The origin request policy CloudFront documents for a Lambda function URL origin: forwarding the
#: viewer's Host header would break the sigv4 signature the OAC computes.
_ALL_VIEWER_EXCEPT_HOST = "Managed-AllViewerExceptHostHeader"

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]

#: The origin echoes back the marker it was given and the header names it saw, which is what turns
#: "the CDN answered 200" into "the request reached the customer's code through CloudFront".
_FUNCTION_SOURCE = '''\
import json
import os


def handler(event, context):
    headers = event["headers"]
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({
            "marker": os.environ["SIM2REAL_MARKER"],
            "header_names": sorted(headers),
        }),
    }
'''


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _zip_source(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", source)
    return buf.getvalue()


def _managed_origin_request_policy_id(cf, name: str) -> str:
    """Resolve a managed origin request policy id by name from the target's own catalogue."""
    marker = None
    while True:
        kwargs = {"Type": "managed", "MaxItems": "100"}
        if marker is not None:
            kwargs["Marker"] = marker
        page = cf.list_origin_request_policies(**kwargs)["OriginRequestPolicyList"]
        for item in page["Items"]:
            if item["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["Name"] == name:
                return item["OriginRequestPolicy"]["Id"]
        marker = page.get("NextMarker")
        if marker is None:
            raise AssertionError(
                f"the managed origin request policy {name!r} is required for a Lambda function URL "
                f"origin (the Host header must not be forwarded) and the target's managed catalogue "
                f"does not list it"
            )


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An OAC of type 'lambda' signs the CDN's origin request; the same URL unsigned is refused 403
    {"Message": "Forbidden"}, and the CDN path still answers 200 afterwards. The function echoes this
    run's marker and an x-amz-cf-id header, proving CloudFront called it.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-lambda.html
    """
    cf = ctx.client("cloudfront")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    marker = ctx.unique_name("sim2real-oac-lambda-marker-")

    role_name = ctx.unique_name("sim2real-behav-cflam-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real lambda function URL behind CloudFront OAC",
        Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    function_name = ctx.unique_name("sim2real-behav-cflam-fn-")

    def create_function():
        """Create the function, tolerating ONLY the IAM propagation error."""
        try:
            return lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_source(_FUNCTION_SOURCE)},
                Timeout=10,
                Environment={"Variables": {"SIM2REAL_MARKER": marker}},
                Tags={t["Key"]: t["Value"] for t in _TAG_SET},
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidParameterValueException":
                raise
            # Lambda reports a not-yet-propagated execution role as
            # InvalidParameterValueException. Every other code is a real failure, re-raised above.
            return None

    created = _poll_until(
        create_function, lambda r: r is not None, timeout_s=180.0, interval_s=10.0,
        description=f"CreateFunction to accept the freshly created role {role_name}",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))
    assert created["FunctionArn"].split(":")[4] == account, (
        f"expected the function to belong to the calling account {account}, got "
        f"{created['FunctionArn']!r}"
    )
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda state: state == "Active",
        timeout_s=180.0, interval_s=5.0,
        description=f"lambda function {function_name} to become Active before it can be invoked",
    )

    function_url = lam.create_function_url_config(
        FunctionName=function_name, AuthType="AWS_IAM")["FunctionUrl"]
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function_url_config(
        FunctionName=function_name))
    origin_host = urllib.parse.urlparse(function_url).netloc
    assert origin_host != "", (
        f"CreateFunctionUrlConfig must return an absolute https URL to use as an origin domain, got "
        f"{function_url!r}"
    )

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cflam-oac-"),
        "OriginAccessControlOriginType": "lambda",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))
    stored_oac = cf.get_origin_access_control(Id=oac_id)["OriginAccessControl"]
    stored_type = stored_oac["OriginAccessControlConfig"]["OriginAccessControlOriginType"]
    assert stored_type == "lambda", (
        f"expected the origin access control stored with OriginAccessControlOriginType 'lambda', "
        f"got {stored_type!r}"
    )

    orp_id = _managed_origin_request_policy_id(cf, _ALL_VIEWER_EXCEPT_HOST)

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cflam-cr-"),
        "Comment": "sim2real OAC signs a lambda function URL origin",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "lambdaurl",
            "DomainName": origin_host,
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                "OriginReadTimeout": 30,
                "OriginKeepaliveTimeout": 5,
            },
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "lambdaurl",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_DISABLED,
            # Without this the viewer's Host header would reach the origin and invalidate the sigv4
            # signature the OAC computes over the function URL's own host.
            "OriginRequestPolicyId": orp_id,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})

    # The resource policy is scoped to THIS distribution, so the grant cannot be what admits an
    # arbitrary caller. Two statements are required: CloudFront's docs for OAC-signed Lambda
    # function URL origins grant BOTH InvokeFunctionUrl and InvokeFunction to the service
    # principal — a distribution with only the former still gets Lambda's generic Forbidden on
    # every signed request, which is indistinguishable from an unsigned one without this grant.
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-allow-cloudfront-oac-url",
        Action="lambda:InvokeFunctionUrl",
        Principal="cloudfront.amazonaws.com",
        SourceArn=dist["ARN"],
        FunctionUrlAuthType="AWS_IAM",
    )
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-allow-cloudfront-oac-fn",
        Action="lambda:InvokeFunction",
        Principal="cloudfront.amazonaws.com",
        SourceArn=dist["ARN"],
    )

    _wait_distribution_deployed(cf, dist_id)

    session = requests.Session()
    cdn_url, route_headers = ctx.endpoint_route(f"{domain}/")
    session.headers.update(route_headers)

    def cdn_probe():
        try:
            return session.get(cdn_url, timeout=20)
        except requests.RequestException as exc:  # transport only, during edge propagation
            return exc

    try:
        admitted = _poll_until(
            cdn_probe,
            lambda r: isinstance(r, requests.Response) and r.status_code == 200,
            timeout_s=240.0, interval_s=5.0,
            description="200 through the distribution for the OAC-signed lambda URL origin",
        )
    except AssertionError as exc:
        last = cdn_probe()
        detail = (
            f"status={last.status_code} body={last.text[:500]!r}"
            if isinstance(last, requests.Response)
            else repr(last)
        )
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc} | last probe: {detail}") from exc

    payload = json.loads(admitted.text)
    assert payload["marker"] == marker, (
        f"the origin must be the function this run created, identified by the marker it was given: "
        f"expected {marker!r}, got {payload['marker']!r}"
    )
    header_names = payload["header_names"]
    assert "x-amz-cf-id" in header_names, (
        f"the invocation must have arrived through CloudFront, which adds x-amz-cf-id to the origin "
        f"request; the function saw {header_names!r} — without it a target could pass this leg by "
        f"letting the test client reach the function directly"
    )

    _url, _route = ctx.endpoint_route(function_url)
    direct = requests.get(_url, timeout=20, headers=_route)
    assert direct.status_code == 403, (
        f"the function URL's AuthType is AWS_IAM and only the OAC signs, so an unsigned direct call "
        f"must be refused: expected 403, got {direct.status_code} / {direct.text[:200]!r}"
    )
    assert json.loads(direct.text) == {"Message": "Forbidden"}, (
        f"the refusal must be the AWS_IAM authorizer's Forbidden body, got {direct.text[:200]!r}"
    )

    assert marker not in direct.text, (
        f"the refused direct call returned the function's own payload: {direct.text[:200]!r}"
    )

    restored = session.get(cdn_url, timeout=20)
    assert restored.status_code == 200, (
        f"after the refused direct call the CDN path must still answer: expected 200, got "
        f"{restored.status_code} / {restored.text[:200]!r}"
    )
    assert json.loads(restored.text)["marker"] == marker, (
        f"expected the same marker {marker!r} on the restore leg, got {restored.text[:200]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
