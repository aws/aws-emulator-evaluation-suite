"""list-routing-rules-reflects-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-routing-rules-reflects-created"
GROUP = "data-plane"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
ACM_TAGS = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRoutingRules immediately reflects a newly created RoutingRule and stops
    listing it after DeleteRoutingRule."""
    apigw = ctx.client("apigatewayv2")

    domain = ctx.unique_name("sim2real-behav-") + ".example.com"
    cert_arn = _import_self_signed_cert(ctx, domain)
    _create_domain_name_with_retry(apigw, domain, cert_arn)
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain))

    # RoutingRule's InvokeApi action only accepts REST-protocol (API Gateway v1)
    # targets ("Invalid API protocol type. Only the REST protocol type is
    # supported"), not an apigatewayv2 HTTP API.
    api = _create_basic_rest_api(ctx)

    rule = apigw.create_routing_rule(
        DomainName=domain,
        Priority=7,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["listed"]}}],
        Actions=[{"InvokeApi": {"ApiId": api["api_id"], "Stage": api["stage"]}}],
    )
    rule_id = rule["RoutingRuleId"]

    def _cleanup():
        try:
            apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    ids = {r["RoutingRuleId"] for r in _list_all_routing_rules(apigw, domain)}
    assert rule_id in ids, f"expected {rule_id!r} in ListRoutingRules, got {sorted(ids)!r}"

    apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=rule_id)

    ids_after = {r["RoutingRuleId"] for r in _list_all_routing_rules(apigw, domain)}
    assert rule_id not in ids_after, (
        f"expected {rule_id!r} absent from ListRoutingRules after delete, got {sorted(ids_after)!r}"
    )

    err = _error(lambda: apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id))
    assert err == ("NotFoundException", "Unable to find RoutingRule."), (
        f"expected NotFoundException for deleted {rule_id!r}, got {err!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _self_signed_cert(domain: str) -> tuple[bytes, bytes]:
    import subprocess
    import tempfile
    import os as _os

    with tempfile.TemporaryDirectory() as d:
        key_path = _os.path.join(d, "key.pem")
        cert_path = _os.path.join(d, "cert.pem")
        try:
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "365",
                    "-nodes", "-keyout", key_path, "-out", cert_path, "-subj", f"/CN={domain}",
                ],
                check=True,
                capture_output=True,
            )
        except FileNotFoundError:
            raise AssertionError(
                "openssl CLI not available to generate a self-signed certificate for ACM import"
            )
        with open(key_path, "rb") as f:
            key = f.read()
        with open(cert_path, "rb") as f:
            cert = f.read()
    return cert, key


def _import_self_signed_cert(ctx, domain: str) -> str:
    cert, key = _self_signed_cert(domain)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert, PrivateKey=key, Tags=ACM_TAGS)
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_with_retry(acm, arn))
    return arn


def _delete_cert_with_retry(acm, cert_arn):
    # The domain name referencing this cert is deleted just before this cleanup runs
    # (LIFO), but ACM can take a few seconds to stop reporting the cert as in-use.
    import time

    from botocore.exceptions import ClientError

    for _ in range(6):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "ResourceInUseException":
                raise
            time.sleep(3)
    raise RuntimeError(f"cert {cert_arn!r} still ResourceInUseException after retries")


def _create_basic_rest_api(ctx):
    """A minimal REST (API Gateway v1) API with a deployed stage — the kind of
    target RoutingRule's InvokeApi action requires."""
    apigw1 = ctx.client("apigateway")
    api = apigw1.create_rest_api(name=ctx.unique_name("sim2real-behav-"), tags=TAGS)
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
                Tags=TAGS,
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "TooManyRequestsException":
                last_exc = e
                _time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            raise
    raise last_exc


def _list_all_routing_rules(apigw, domain):
    items = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = apigw.list_routing_rules(DomainName=domain, **kwargs)
        items.extend(resp.get("RoutingRules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
