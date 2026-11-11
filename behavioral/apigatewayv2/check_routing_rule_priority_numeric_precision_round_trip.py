"""routing-rule-priority-numeric-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "routing-rule-priority-numeric-precision-round-trip"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RoutingRule Priority set to the documented boundary values (min=1, max=1000000)
    is persisted and returned by GetRoutingRule with exact numeric equality."""
    apigw = ctx.client("apigatewayv2")

    domain = ctx.unique_name("sim2real-behav-") + ".example.com"
    cert_arn = _import_self_signed_cert(ctx, domain)
    _create_domain_name_with_retry(apigw, domain, cert_arn)
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain))

    # RoutingRule's InvokeApi action only accepts REST-protocol (API Gateway v1)
    # targets ("Invalid API protocol type. Only the REST protocol type is
    # supported"), not an apigatewayv2 HTTP API.
    api = _create_basic_rest_api(ctx)

    low = apigw.create_routing_rule(
        DomainName=domain,
        Priority=1,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["low"]}}],
        Actions=[{"InvokeApi": {"ApiId": api["api_id"], "Stage": api["stage"]}}],
    )
    low_id = low["RoutingRuleId"]
    ctx.on_cleanup(lambda: apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=low_id))

    high = apigw.create_routing_rule(
        DomainName=domain,
        Priority=1000000,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["high"]}}],
        Actions=[{"InvokeApi": {"ApiId": api["api_id"], "Stage": api["stage"]}}],
    )
    high_id = high["RoutingRuleId"]
    ctx.on_cleanup(lambda: apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=high_id))

    assert low["Priority"] == 1 and type(low["Priority"]) is int, (
        f"expected CreateRoutingRule to echo Priority=1 (int), got {low['Priority']!r} "
        f"({type(low['Priority'])})"
    )
    assert high["Priority"] == 1000000 and type(high["Priority"]) is int, (
        f"expected CreateRoutingRule to echo Priority=1000000 (int), got {high['Priority']!r} "
        f"({type(high['Priority'])})"
    )

    got_low = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=low_id)
    got_high = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=high_id)
    assert got_low["Priority"] == 1 and type(got_low["Priority"]) is int, (
        f"expected independent GetRoutingRule to return the min-boundary Priority=1 (int) "
        f"unchanged, got {got_low['Priority']!r} ({type(got_low['Priority'])})"
    )
    assert got_high["Priority"] == 1000000 and type(got_high["Priority"]) is int, (
        f"expected independent GetRoutingRule to return the max-boundary Priority=1000000 (int) "
        f"unchanged, got {got_high['Priority']!r} ({type(got_high['Priority'])})"
    )


def _self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    import subprocess
    import tempfile
    import os as _os

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
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
        Certificate=cert, PrivateKey=key, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=arn))
    return arn


def _create_basic_rest_api(ctx):
    """A minimal REST (API Gateway v1) API with a deployed stage — the kind of
    target RoutingRule's InvokeApi action requires."""
    apigw1 = ctx.client("apigateway")
    api = apigw1.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw1.delete_rest_api(restApiId=api_id))

    root_id = apigw1.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw1.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw1.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw1.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw1.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    stage_name = "prod"
    apigw1.create_deployment(restApiId=api_id, stageName=stage_name)
    return {"api_id": api_id, "stage": stage_name}


def _create_domain_name_with_retry(apigw, domain, cert_arn, attempts=6):
    """CreateDomainName is tightly rate-limited per account; back off and retry
    on TooManyRequestsException instead of treating a transient throttle as a
    check bug."""
    import time as _time

    from botocore.exceptions import ClientError

    delay = 5.0
    last_exc = None
    for _ in range(attempts):
        try:
            return apigw.create_domain_name(
                DomainName=domain,
                DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
                # RoutingRule creation is rejected on a domain whose RoutingMode
                # still defaults to API_MAPPING_ONLY.
                RoutingMode="ROUTING_RULE_ONLY",
                Tags={"sim2real": CHECK},
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "TooManyRequestsException":
                last_exc = e
                _time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
