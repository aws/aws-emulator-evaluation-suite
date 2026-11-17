"""rest-and-http-api-custom-domains-route-mapped-paths-to-iam-authorized-routes."""
from __future__ import annotations

import http.client
import io
import json
import socket
import ssl
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rest-and-http-api-custom-domains-route-mapped-paths-to-iam-authorized-routes"
GROUP = "data-plane"
SERVICES = ["acm", "apigateway", "apigatewayv2", "iam", "lambda", "route53"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_THROTTLE_CODES = ("TooManyRequestsException", "ThrottlingException", "Throttling")
_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_ROLE_NOT_READY = ("cannot be assumed", "does not have permissions")
_HANDLER_SRC = r'''
import os


def handler(event, context):
    return {"statusCode": 200, "headers": {"content-type": "text/plain"}, "body": os.environ["MARKER"]}
'''


# ===== helpers (self-contained) =====


def _retry_throttle(fn, *, attempts=8, base_delay=3.0):
    """Call fn(), retrying only a throttle code with linear backoff."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (attempt + 1))
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); return it. RAISES on timeout, never returns stale."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _dns_baseline(route53):
    """(apex, zone id) of the public zone carrying _BASELINE_TAG. Fails, never skips, when the
    account has none."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            if zone["Config"].get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=zone_id
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                return zone["Name"].rstrip("."), zone_id
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has no domain to "
        "serve a custom domain on"
    )


def _change(route53, zone_id, action, rrset):
    """One ChangeResourceRecordSets of a single record set; returns the change id."""
    return route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": action, "ResourceRecordSet": rrset}]},
    )["ChangeInfo"]["Id"]


def _delete_certificate_when_free(ctx, acm, cert_arn):
    """Delete cert_arn once ACM lists no user of it: a deleted custom domain releases it a while
    later. RAISES if it is still in use when the cleanup budget ends."""
    try:
        _poll_until(
            ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
            lambda users: users == [], timeout_s=900, interval_s=15,
            description=f"certificate {cert_arn} released by its users",
        )
        acm.delete_certificate(CertificateArn=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _issue_certificate(ctx, acm, route53, zone_id, names):
    """A publicly issued, DNS-validated certificate for every name in names. Registers the
    validation records' and the certificate's cleanup, the certificate's to run first."""
    cert_arn = _retry_throttle(lambda: acm.request_certificate(
        DomainName=names[0], SubjectAlternativeNames=names, ValidationMethod="DNS", Tags=_TAGS,
    ))["CertificateArn"]
    options = _poll_until(
        ctx,
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]
        .get("DomainValidationOptions", []),
        lambda opts: len(opts) == len(names) and all("ResourceRecord" in o for o in opts),
        timeout_s=120, interval_s=5, description="ACM publishing the DNS validation records",
    )
    records = {o["ResourceRecord"]["Name"]: o["ResourceRecord"] for o in options}
    for record in records.values():
        rrset = {"Name": record["Name"], "Type": record["Type"], "TTL": 60,
                 "ResourceRecords": [{"Value": record["Value"]}]}
        ctx.on_cleanup(_teardown(lambda r=rrset: _change(route53, zone_id, "DELETE", r),
                                 "InvalidChangeBatch"))
        _change(route53, zone_id, "UPSERT", rrset)
    ctx.on_cleanup(lambda: _delete_certificate_when_free(ctx, acm, cert_arn))
    issued = _poll_until(
        ctx, lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda c: c["Status"] != "PENDING_VALIDATION", timeout_s=900, interval_s=15,
        description=f"the certificate for {names!r} leaving PENDING_VALIDATION",
    )
    assert issued["Status"] == "ISSUED", (
        f"a certificate whose validation records are published must be ISSUED; got "
        f"{issued['Status']!r} ({issued.get('FailureReason')!r})"
    )
    return cert_arn


def _caller_credentials(ctx):
    """The harness's per-run credentials, through the one sanctioned seam."""
    env = ctx.subprocess_env()
    akid, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
    assert akid and secret, "ctx.subprocess_env() carried no credentials to sign with"
    return akid, secret, env.get("AWS_SESSION_TOKEN")


def _signed(ctx, host, path):
    """The headers of a GET of https://{host}{path}, SigV4-signed for execute-api."""
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    # tls: the signature covers the custom domain the request is sent on
    request = AWSRequest(method="GET", url=f"https://{host}{path}", headers={"Host": host})
    SigV4Auth(Credentials(*_caller_credentials(ctx)), "execute-api", ctx.region).add_auth(request)
    return {k: v for k, v in request.headers.items() if k.lower() != "host"}


def _zipped(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _delete_role(iam, name):
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_log_group(ctx, fn_name):
    """The function's log group, if an invocation created one; its role grants no logging, so
    normally there is none."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _deploy_function(ctx, marker):
    """A function returning marker as a text/plain 200, under a role with no permissions."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = ctx.unique_name("sim2real-behav-apidom-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST), Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    fn_name = ctx.unique_name("sim2real-behav-apidom-fn-")
    deadline = time.monotonic() + _budget_s(ctx, 120)
    while True:
        try:
            fn_arn = lam.create_function(
                FunctionName=fn_name, Runtime="python3.12", Handler="index.handler",
                Role=role_arn, Code={"ZipFile": _zipped(_HANDLER_SRC)}, Timeout=10,
                Environment={"Variables": {"MARKER": marker}},
                Tags={t["Key"]: t["Value"] for t in _TAGS},
            )["FunctionArn"]
            break
        except ClientError as exc:
            # A role created seconds ago is not yet assumable by Lambda; no API reports when it is.
            propagating = exc.response["Error"]["Code"] == "InvalidParameterValueException" and any(
                s in exc.response["Error"]["Message"] for s in _ROLE_NOT_READY
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_log_group(ctx, fn_name))
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    state = _poll_until(
        ctx, lambda: lam.get_function_configuration(FunctionName=fn_name)["State"],
        lambda s: s in ("Active", "Failed"), timeout_s=180, interval_s=3,
        description="the integration function becoming Active",
    )
    assert state == "Active", f"the integration function ended {state!r}"
    return lam, fn_name, fn_arn


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


# tls-subject: the certificate served for the custom names is graded, so the connection
# verifies the chain and the hostname with ctx.http_verify, SNI and Host set to that name.
def _https_get(ctx, published_host, name, path, headers=None):
    """GET https://{name}{path} sent to the published host with SNI and Host set to name, the
    served certificate verified for name. Returns (status, headers, body, peer certificate)."""
    extra = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    with socket.create_connection(ctx.endpoint_host(published_host, 443), timeout=15) as raw:
        with _https_context(ctx.http_verify).wrap_socket(raw, server_hostname=name) as tls:
            peer = tls.getpeercert()
            tls.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: sim2real-behav\r\n{extra}"
                f"Connection: close\r\n\r\n".encode()
            )
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, body, peer


def _poll_https(ctx, published_host, name, path, accept, description, *, signed=False):
    """Poll _https_get until accept(status, body): a custom domain's mapping can take a while to
    route after the domain is AVAILABLE. Transport and TLS errors are retried; RAISES on deadline."""
    last = None
    deadline = time.monotonic() + _budget_s(ctx, 300)
    while time.monotonic() < deadline:
        try:
            headers = _signed(ctx, name, path) if signed else None
            result = _https_get(ctx, published_host, name, path, headers)
        except (OSError, http.client.HTTPException) as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if accept(result[0], result[2]):
                return result
            last = (result[0], result[2][:300])
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description}: never settled. Last: {last!r}")


@tags(
    "axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint",
    "plane:data", "requires:dns-baseline",
)
def run(ctx) -> None:
    """A REGIONAL REST custom domain's base path mapping and an HTTP API custom domain's API
    mapping key route a signed request to an AWS_IAM route with 200, refuse an unsigned one with
    each API type's 403 envelope, and serve the issued ACM certificate on each name.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-mappings.html
    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mappings.html
    """
    acm = ctx.client("acm")
    apigw = ctx.client("apigateway")
    apigw2 = ctx.client("apigatewayv2")
    route53 = ctx.client("route53")

    apex, zone_id = _dns_baseline(route53)
    rest_name = f"{ctx.unique_name('sim2real')[:16]}.{apex}"
    http_name = f"{ctx.unique_name('sim2real')[:16]}.{apex}"
    assert len(rest_name) <= 64, f"ACM caps a certificate's first name at 64 octets; {rest_name!r}"
    rest_marker = f"sim2real rest {rest_name.split('.')[0]}"
    http_marker = f"sim2real http {http_name.split('.')[0]}"

    cert_arn = _issue_certificate(ctx, acm, route53, zone_id, [rest_name, http_name])

    # REST API: GET /items is AWS_IAM-authorized and answers a fixed mock response.
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apidom-rest-"),
        endpointConfiguration={"types": ["REGIONAL"]}, disableExecuteApiEndpoint=True,
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_teardown(
        lambda: _retry_throttle(lambda: apigw.delete_rest_api(restApiId=api_id)),
        "NotFoundException",
    ))
    root_id = next(i["id"] for i in apigw.get_resources(restApiId=api_id)["items"] if i["path"] == "/")
    items_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="items")["id"]
    apigw.put_method(restApiId=api_id, resourceId=items_id, httpMethod="GET",
                     authorizationType="AWS_IAM")
    apigw.put_integration(restApiId=api_id, resourceId=items_id, httpMethod="GET", type="MOCK",
                          requestTemplates={"application/json": '{"statusCode": 200}'})
    apigw.put_method_response(restApiId=api_id, resourceId=items_id, httpMethod="GET",
                              statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=items_id, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": rest_marker},
    )
    apigw.create_deployment(restApiId=api_id, stageName="live")

    apigw.create_domain_name(
        domainName=rest_name, regionalCertificateArn=cert_arn,
        endpointConfiguration={"types": ["REGIONAL"]}, securityPolicy="TLS_1_2",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(
        lambda: _retry_throttle(lambda: apigw.delete_domain_name(domainName=rest_name)),
        "NotFoundException",
    ))
    apigw.create_base_path_mapping(domainName=rest_name, basePath="v1", restApiId=api_id,
                                   stage="live")
    ctx.on_cleanup(_teardown(
        lambda: _retry_throttle(
            lambda: apigw.delete_base_path_mapping(domainName=rest_name, basePath="v1")
        ),
        "NotFoundException",
    ))

    # HTTP API: GET /items is AWS_IAM-authorized and proxies to a function returning a marker.
    lam, fn_name, fn_arn = _deploy_function(ctx, http_marker)
    http_api_id = apigw2.create_api(
        Name=ctx.unique_name("sim2real-behav-apidom-http-"), ProtocolType="HTTP",
        DisableExecuteApiEndpoint=True, Tags={"sim2real": CHECK},
    )["ApiId"]
    ctx.on_cleanup(_teardown(
        lambda: _retry_throttle(lambda: apigw2.delete_api(ApiId=http_api_id)),
        "NotFoundException",
    ))
    integration_id = apigw2.create_integration(
        ApiId=http_api_id, IntegrationType="AWS_PROXY", IntegrationUri=fn_arn,
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    apigw2.create_route(ApiId=http_api_id, RouteKey="GET /items", AuthorizationType="AWS_IAM",
                        Target=f"integrations/{integration_id}")
    apigw2.create_stage(ApiId=http_api_id, StageName="live", AutoDeploy=True)
    partition = fn_arn.split(":")[1]
    lam.add_permission(
        FunctionName=fn_name, StatementId="apigateway-invoke", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:{partition}:execute-api:{ctx.region}:{ctx.account}:{http_api_id}/*/GET/items",
    )

    apigw2.create_domain_name(
        DomainName=http_name,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL",
                                   "SecurityPolicy": "TLS_1_2"}],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(
        lambda: _retry_throttle(lambda: apigw2.delete_domain_name(DomainName=http_name)),
        "NotFoundException",
    ))
    mapping_id = apigw2.create_api_mapping(
        DomainName=http_name, ApiId=http_api_id, Stage="live", ApiMappingKey="v2",
    )["ApiMappingId"]
    ctx.on_cleanup(_teardown(
        lambda: _retry_throttle(
            lambda: apigw2.delete_api_mapping(DomainName=http_name, ApiMappingId=mapping_id)
        ),
        "NotFoundException",
    ))

    # (1) The mappings read back as created.
    mappings = apigw.get_base_path_mappings(domainName=rest_name)["items"]
    assert mappings == [{"basePath": "v1", "restApiId": api_id, "stage": "live"}], (
        f"the REST domain must hold exactly the v1 mapping; got {mappings!r}"
    )
    v2_mappings = [
        {k: m[k] for k in ("ApiId", "ApiMappingId", "ApiMappingKey", "Stage")}
        for m in apigw2.get_api_mappings(DomainName=http_name)["Items"]
    ]
    assert v2_mappings == [{"ApiId": http_api_id, "ApiMappingId": mapping_id,
                            "ApiMappingKey": "v2", "Stage": "live"}], (
        f"the HTTP API domain must hold exactly the v2 mapping; got {v2_mappings!r}"
    )

    rest_host = _poll_until(
        ctx, lambda: _retry_throttle(lambda: apigw.get_domain_name(domainName=rest_name)),
        lambda d: d.get("domainNameStatus") == "AVAILABLE", timeout_s=600, interval_s=5,
        description=f"the REST custom domain {rest_name!r} reaching AVAILABLE",
    )["regionalDomainName"]
    http_host = _poll_until(
        ctx,
        lambda: _retry_throttle(lambda: apigw2.get_domain_name(DomainName=http_name))
        ["DomainNameConfigurations"][0],
        lambda c: c.get("DomainNameStatus") == "AVAILABLE", timeout_s=600, interval_s=5,
        description=f"the HTTP API custom domain {http_name!r} reaching AVAILABLE",
    )["ApiGatewayDomainName"]

    # A REST method answers an unsigned caller with its missing-token envelope, an HTTP API route
    # with a plain Forbidden.
    for host, name, path, marker, refusal in (
        (rest_host, rest_name, "/v1/items", rest_marker, {"message": "Missing Authentication Token"}),
        (http_host, http_name, "/v2/items", http_marker, {"message": "Forbidden"}),
    ):
        # (2) A signed request through the mapping reaches the route, over the issued certificate.
        status, _headers, body, peer = _poll_https(
            ctx, host, name, path, lambda s, _b: s == 200,
            f"a signed GET {path} on the custom domain being served",
            signed=True,
        )
        assert body == marker.encode(), f"GET {path} must return the route's marker; got {body!r}"
        subject_names = sorted(v for kind, v in peer.get("subjectAltName", ()) if kind == "DNS")
        assert subject_names == sorted([rest_name, http_name]), (
            f"the served certificate must name exactly the two custom names; SANs {subject_names!r}"
        )

        # (3) The same request unsigned is refused before the integration runs. Polled: a fresh
        #     connection can still reach a front end that does not serve the name yet.
        status, headers, body, _peer = _poll_https(
            ctx, host, name, path, lambda s, _b: s == 403,
            f"an unsigned GET {path} on the custom domain being refused",
        )
        assert status == 403 and marker.encode() not in body, (
            f"an unsigned GET {path} on an AWS_IAM route must be refused with 403; got {status} "
            f"{body[:300]!r}"
        )
        assert json.loads(body) == refusal, (
            f"the unsigned refusal of GET {path} must be {refusal!r}; got {body[:300]!r} "
            f"{headers.get('x-amzn-errortype')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
