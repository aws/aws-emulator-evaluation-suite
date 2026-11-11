"""put-routing-rule-nonexistent-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-routing-rule-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRoutingRule against a routing rule id that was never created returns
    NotFoundException, no such rule appears on the domain, and PutRoutingRule against a
    rule that actually exists succeeds (positive control)."""
    apigw = ctx.client("apigatewayv2")

    domain = f"{ctx.unique_name('sim2real-behav-')}.example.com"
    _create_domain(ctx, apigw, domain)

    stage = "prod"
    api_id = _create_rest_api_stage(ctx, stage)
    actions = [{"InvokeApi": {"ApiId": api_id, "Stage": stage}}]
    conditions = [{"MatchBasePaths": {"AnyOf": ["a"]}}]


    bogus_rule_id = "zzzzzzzzzz9999999999"
    err = _error(
        lambda: apigw.put_routing_rule(
            DomainName=domain,
            RoutingRuleId=bogus_rule_id,
            Priority=1,
            Actions=actions,
            Conditions=conditions,
        )
    )
    assert err == ("NotFoundException", "Unable to find RoutingRule."), (
        f"expected NotFoundException, got {err!r}"
    )

    # effect absent: no rule with that id (or any rule at all) exists on the domain
    rules = apigw.list_routing_rules(DomainName=domain).get("RoutingRules", [])
    rule_ids = [r["RoutingRuleId"] for r in rules]
    assert bogus_rule_id not in rule_ids, (
        f"bogus rule id {bogus_rule_id!r} unexpectedly present in {rule_ids!r}"
    )

    # positive control: PutRoutingRule against a rule that actually exists succeeds
    created = apigw.create_routing_rule(
        DomainName=domain, Priority=1, Actions=actions, Conditions=conditions
    )
    real_rule_id = created["RoutingRuleId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=real_rule_id)
        )
    )
    new_conditions = [{"MatchBasePaths": {"AnyOf": ["b"]}}]
    apigw.put_routing_rule(
        DomainName=domain,
        RoutingRuleId=real_rule_id,
        Priority=1,
        Actions=actions,
        Conditions=new_conditions,
    )

    # terminal read is independent of the mutating PutRoutingRule call
    got = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=real_rule_id)
    got_paths = got["Conditions"][0]["MatchBasePaths"]["AnyOf"]
    assert got_paths == ["b"], f"expected persisted conditions ['b'], got {got_paths!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn) -> None:
    """Teardown tolerance for a resource that is already gone; any other error stays loud."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _ignore_client_error(fn) -> None:
    """Best-effort teardown: the resource may already be gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


def _create_rest_api_stage(ctx, stage_name):
    """RoutingRule's InvokeApi action only targets REST (v1) APIs, not HTTP APIs."""
    apigw1 = ctx.client("apigateway")
    api_id = apigw1.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))["id"]
    ctx.on_cleanup(lambda: _ignore_client_error(lambda: apigw1.delete_rest_api(restApiId=api_id)))

    root_id = next(
        r["id"] for r in apigw1.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    apigw1.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw1.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw1.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw1.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw1.create_deployment(restApiId=api_id, stageName=stage_name)
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: apigw1.delete_stage(restApiId=api_id, stageName=stage_name)
        )
    )
    return api_id



def _create_domain(ctx, apigw, domain):
    acm = ctx.client("acm")
    cert_pem, key_pem = _self_signed_cert(domain)
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)[
        "CertificateArn"
    ]
    # ACM reports this certificate in use for over 40s after the routing-rule domain is
    # deleted, longer than the cleanup budget allows, so this delete is best-effort.
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    )
    created = _retrying(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}
            ],
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=domain)))
    # routing rules require the domain's RoutingMode to enable rule evaluation
    apigw.update_domain_name(DomainName=domain, RoutingMode="ROUTING_RULE_THEN_API_MAPPING")
    return created



def _retrying(fn, *, retries=6, base_delay=3.0):
    import time

    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return fn()
        except ClientError as e:
            if (
                e.response["Error"]["Code"] == "TooManyRequestsException"
                and attempt < retries - 1
            ):
                time.sleep(base_delay * (attempt + 1))
                continue
            raise



def _self_signed_cert(domain):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem




if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
