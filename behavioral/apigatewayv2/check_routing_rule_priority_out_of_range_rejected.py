"""routing-rule-priority-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "routing-rule-priority-out-of-range-rejected"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoutingRule rejects a Priority above the documented maximum (1000000) with
    BadRequestException, creates no rule, while a boundary-valid Priority still succeeds."""
    apigw = ctx.client("apigatewayv2")

    domain = ctx.unique_name("sim2real-behav-") + ".example.com"
    cert_arn = _import_self_signed_cert(ctx, domain)
    _create_domain_name_with_retry(apigw, domain, cert_arn)
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain))

    # RoutingRule's InvokeApi action only accepts REST-protocol (API Gateway v1)
    # targets ("Invalid API protocol type. Only the REST protocol type is
    # supported"), not an apigatewayv2 HTTP API.
    api = _create_basic_rest_api(ctx)

    before = {r["RoutingRuleId"] for r in _list_all_routing_rules(apigw, domain)}

    code, message = _error_code(
        lambda: apigw.create_routing_rule(
            DomainName=domain,
            Priority=1000001,
            Conditions=[{"MatchBasePaths": {"AnyOf": ["toohigh"]}}],
            Actions=[{"InvokeApi": {"ApiId": api["api_id"], "Stage": api["stage"]}}],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException for Priority=1000001, got {code!r}"
    expected_message = "Priority must be between 1 and 1,000,000."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    after = {r["RoutingRuleId"] for r in _list_all_routing_rules(apigw, domain)}
    assert after == before, "an out-of-range Priority must not create a routing rule"

    # Positive control: a valid, in-range Priority on the same domain succeeds.
    ok = apigw.create_routing_rule(
        DomainName=domain,
        Priority=500000,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["ok"]}}],
        Actions=[{"InvokeApi": {"ApiId": api["api_id"], "Stage": api["stage"]}}],
    )
    ok_id = ok["RoutingRuleId"]
    ctx.on_cleanup(lambda: apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=ok_id))
    assert ok["Priority"] == 500000, f"expected create response Priority 500000, got {ok.get('Priority')!r}"

    # Terminal read: an independent ListRoutingRules call, not the mutating call's own
    # response, confirms the accepted rule actually landed at the destination.
    landed = {r["RoutingRuleId"]: r for r in _list_all_routing_rules(apigw, domain)}
    assert ok_id in landed, f"expected {ok_id} to appear in ListRoutingRules, got {sorted(landed)}"
    assert landed[ok_id]["Priority"] == 500000, (
        f"expected the listed rule's Priority to be 500000, got {landed[ok_id].get('Priority')!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
        Certificate=cert, PrivateKey=key, Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}]
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_after_unlink(acm, arn))
    return arn


def _delete_cert_after_unlink(acm, cert_arn: str, *, attempts: int = 8, base_delay: float = 6.0) -> None:
    """ACM keeps a certificate in use for a while after the domain name that referenced it
    is deleted; retry through that window, then leave the tagged certificate behind
    rather than failing the teardown."""
    import time

    from botocore.exceptions import ClientError

    for attempt in range(attempts):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and attempt < attempts - 1:
                time.sleep(base_delay)
                continue
            if code == "ResourceInUseException":
                return
            raise


def _create_basic_rest_api(ctx):
    """A minimal REST (API Gateway v1) API with a deployed stage — the kind of
    target RoutingRule's InvokeApi action requires."""
    apigw1 = ctx.client("apigateway")
    api = apigw1.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"), tags={"sim2real-behav-check": CHECK}
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
                Tags={"sim2real-behav-check": CHECK},
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
