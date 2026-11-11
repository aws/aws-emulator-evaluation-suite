"""e2e-custom-domain-mapping-invoke-flow."""
from __future__ import annotations

import socket
import ssl
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "e2e-custom-domain-mapping-invoke-flow"
GROUP = "e2e"
SERVICES = ["apigatewayv2", "apigateway"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A custom DomainName mapped to an HTTP API stage routes HTTPS requests to that stage, and
    DeleteApiMapping removes the mapping from GetApiMappings/GetApiMapping immediately.
    """
    require_tools("openssl")

    apigw = ctx.client("apigatewayv2")
    route53 = ctx.client("route53")

    # Not ".example.com"/".test"/".invalid"/".localhost": Route 53 refuses CreateHostedZone
    # ("InvalidDomainName ... is reserved by AWS!") for any of IANA's reserved documentation/test
    # domains, by suffix match regardless of subdomain.
    domain = ctx.unique_name("sim2real-behav-") + ".sim2real-test.internal"
    cert_arn = _import_self_signed_cert(ctx, domain)

    apigw.create_domain_name(
        DomainName=domain,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
        Tags=TAGS,
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain))

    cfg = _poll_until(
        lambda: apigw.get_domain_name(DomainName=domain)["DomainNameConfigurations"][0],
        lambda c: c.get("DomainNameStatus") == "AVAILABLE",
        timeout_s=300,
        interval_s=10,
    )
    gw_host = cfg["ApiGatewayDomainName"]
    gw_zone = cfg["HostedZoneId"]

    # ApiGatewayDomainName has no public DNS record of its own; it is only a Route 53 alias
    # target, so an in-account alias zone plus TestDNSAnswer yields the IP a client would reach.
    zone_id = _create_alias_zone(ctx, route53, domain, gw_host, gw_zone)
    ip = _resolve_via_route53(route53, zone_id, domain)

    # The stage's upstream is a REST API MOCK stage the check owns, so routing is all that is tested.
    api = _create_basic_http_api(ctx, _mock_backend(ctx, ctx.unique_name("sim2real-behav-upstream-")))

    mapping = apigw.create_api_mapping(ApiId=api["api_id"], DomainName=domain, Stage=api["stage"])
    mapping_id = mapping["ApiMappingId"]

    def _cleanup_mapping():
        try:
            apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup_mapping)

    status = _poll_until(
        lambda: _fetch_status_via_ip(ctx, ip, domain, "/ping"),
        lambda s: s == 200,
        timeout_s=90,
        interval_s=5,
    )
    assert status == 200, f"expected mapped custom domain to route to stage, got HTTP {status}"

    # Only the control plane is asserted after delete: the data plane can keep routing to the
    # deleted mapping's stage for 15+ minutes, longer than any check-sized timeout.
    apigw.delete_api_mapping(ApiMappingId=mapping_id, DomainName=domain)

    remaining = apigw.get_api_mappings(DomainName=domain)["Items"]
    assert not any(m["ApiMappingId"] == mapping_id for m in remaining), (
        f"deleted mapping {mapping_id!r} still present in GetApiMappings: {remaining!r}"
    )

    try:
        apigw.get_api_mapping(ApiMappingId=mapping_id, DomainName=domain)
        raise AssertionError(f"GetApiMapping succeeded for deleted mapping {mapping_id!r}")
    except apigw.exceptions.NotFoundException as exc:
        expected_message = f"Unable to find ApiMapping with ID {mapping_id}"
        got_message = exc.response["Error"]["Message"]
        assert got_message == expected_message, (
            f"expected the exact message {expected_message!r}, got {got_message!r}"
        )


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    import subprocess
    import tempfile
    import os as _os

    with tempfile.TemporaryDirectory() as d:
        key_path = _os.path.join(d, "key.pem")
        cert_path = _os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "365",
                "-nodes", "-keyout", key_path, "-out", cert_path, "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(key_path, "rb") as f:
            key = f.read()
        with open(cert_path, "rb") as f:
            cert = f.read()
    return cert, key


def _import_self_signed_cert(ctx, domain: str) -> str:
    cert, key = _self_signed_cert(domain)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert,
        PrivateKey=key,
        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_unused(acm, arn))
    return arn


def _delete_cert_when_unused(acm, cert_arn: str, budget_s: float = 300.0) -> None:
    """DeleteCertificate 400s with ResourceInUseException for a window after the custom domain
    name that referenced it is deleted, while ACM propagates the disassociation; retry through
    that window instead of leaking the cert."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _create_alias_zone(ctx, route53, domain: str, gw_host: str, gw_zone: str) -> str:
    resp = route53.create_hosted_zone(
        Name=domain,
        CallerReference=ctx.unique_name("sim2real-behav-zone-"),
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=zone_id))

    record = {
        "Name": domain,
        "Type": "A",
        "AliasTarget": {"HostedZoneId": gw_zone, "DNSName": gw_host, "EvaluateTargetHealth": False},
    }
    change = route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": "CREATE", "ResourceRecordSet": record}]},
    )
    ctx.on_cleanup(
        lambda: route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": record}]},
        )
    )

    change_id = change["ChangeInfo"]["Id"]
    _poll_until(
        lambda: route53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda s: s == "INSYNC",
        timeout_s=120,
        interval_s=5,
    )
    return zone_id


def _resolve_via_route53(route53, zone_id: str, domain: str) -> str:
    resp = _poll_until(
        lambda: route53.test_dns_answer(HostedZoneId=zone_id, RecordName=domain, RecordType="A"),
        lambda r: r.get("ResponseCode") == "NOERROR" and r.get("RecordData"),
        timeout_s=60,
        interval_s=5,
    )
    return resp["RecordData"][0]


def _create_basic_http_api(
    ctx,
    integration_uri,
    route_key="GET /ping",
    stage_name="prod",
):
    apigw = ctx.client("apigatewayv2")
    api = apigw.create_api(Name=ctx.unique_name("sim2real-behav-"), ProtocolType="HTTP", Tags=TAGS)
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))
    integ = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri=integration_uri,
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )
    apigw.create_route(ApiId=api_id, RouteKey=route_key, Target=f"integrations/{integ['IntegrationId']}")
    apigw.create_stage(ApiId=api_id, StageName=stage_name, AutoDeploy=True, Tags=TAGS)
    return {
        "api_id": api_id,
        "integration_id": integ["IntegrationId"],
        "stage": stage_name,
        "api_endpoint": api["ApiEndpoint"],
    }


def _fetch_status_via_ip(ctx, ip: str, domain: str, path: str, timeout: float = 15.0) -> int | None:
    """`None` means the request never reached a server — connection refused/reset, or a
    malformed/empty response — which is a retryable "not yet" signal for the poll, distinct from a
    definite HTTP status."""
    context = ssl._create_unverified_context()
    try:
        raw = socket.create_connection(ctx.endpoint_host(ip, 443), timeout=timeout)
    except OSError:
        return None
    try:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            tls.settimeout(timeout)
            tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
    except (OSError, ssl.SSLError):
        return None
    if not data:
        return None
    parts = data.split(b"\r\n", 1)[0].split(b" ")
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    return int(parts[1])


def _mock_backend(ctx, body: str) -> str:
    """The invoke URL of a REST API stage the check owns whose MOCK integration answers GET / with
    200 and ``body``: a backend on the target itself, so the proxy leg never leaves it."""
    ag = ctx.client("apigateway")
    rest_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-backend-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=TAGS,
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, rest_id))
    root = next(r["id"] for r in ag.get_resources(restApiId=rest_id)["items"] if r["path"] == "/")
    ag.put_method(restApiId=rest_id, resourceId=root, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=rest_id, resourceId=root, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(restApiId=rest_id, resourceId=root, httpMethod="GET", statusCode="200")
    ag.put_integration_response(
        restApiId=rest_id, resourceId=root, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": body},
    )
    ag.create_deployment(restApiId=rest_id, stageName="backend")
    return ctx.rest_api_url(rest_id, "backend")


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    """DeleteRestApi is throttled hard per account, so retry within a bounded budget and say so on
    stderr if the API survives, since teardown exceptions are swallowed."""
    import sys

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise RuntimeError(f"rest api {api_id} not deleted: {code}") from exc
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
