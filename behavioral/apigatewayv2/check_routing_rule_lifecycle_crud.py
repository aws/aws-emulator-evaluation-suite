"""routing-rule-lifecycle-crud."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "routing-rule-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoutingRule -> GetRoutingRule reflects the rule -> PutRoutingRule replaces the rule
    body -> DeleteRoutingRule -> GetRoutingRule returns NotFoundException."""
    apigw = ctx.client("apigatewayv2")

    domain = f"{ctx.unique_name('sim2real-behav-')}.example.com"
    _create_domain(ctx, apigw, domain)

    stage = "prod"
    api_id = _create_rest_api_stage(ctx, stage)

    actions = [{"InvokeApi": {"ApiId": api_id, "Stage": stage, "StripBasePath": True}}]
    conditions = [{"MatchBasePaths": {"AnyOf": ["orders"]}}]

    created = apigw.create_routing_rule(
        DomainName=domain, Priority=1, Actions=actions, Conditions=conditions
    )
    rule_id = created["RoutingRuleId"]
    assert created["Priority"] == 1
    assert created["Conditions"][0]["MatchBasePaths"]["AnyOf"] == ["orders"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
        )
    )

    got = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
    assert got["Conditions"][0]["MatchBasePaths"]["AnyOf"] == ["orders"]

    new_conditions = [{"MatchBasePaths": {"AnyOf": ["invoices"]}}]
    put = apigw.put_routing_rule(
        DomainName=domain,
        RoutingRuleId=rule_id,
        Priority=1,
        Actions=actions,
        Conditions=new_conditions,
    )
    assert put["Conditions"][0]["MatchBasePaths"]["AnyOf"] == ["invoices"]

    got2 = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
    assert got2["Conditions"][0]["MatchBasePaths"]["AnyOf"] == ["invoices"]

    apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=rule_id)

    code, message = _error_code(
        lambda: apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
    )
    assert code == "NotFoundException", f"expected NotFoundException on dead-rule read, got {code!r}"
    expected_message = "Unable to find RoutingRule."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    mutate_code, mutate_message = _error_code(
        lambda: apigw.put_routing_rule(
            DomainName=domain,
            RoutingRuleId=rule_id,
            Priority=1,
            Actions=actions,
            Conditions=new_conditions,
        )
    )
    assert mutate_code == "NotFoundException", (
        f"expected NotFoundException mutating a deleted rule, got {mutate_code!r}"
    )
    expected_message = "Unable to find RoutingRule."
    assert mutate_message == expected_message, f"expected {expected_message!r}, got {mutate_message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _best_effort(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


def _create_rest_api_stage(ctx, stage_name):
    """RoutingRule's InvokeApi action only targets REST (v1) APIs, not HTTP APIs."""
    apigw1 = ctx.client("apigateway")
    api_id = apigw1.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"), tags=TAGS
    )["id"]
    ctx.on_cleanup(lambda: _best_effort(lambda: apigw1.delete_rest_api(restApiId=api_id)))

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
        lambda: _best_effort(
            lambda: apigw1.delete_stage(restApiId=api_id, stageName=stage_name)
        )
    )
    return api_id


def _create_domain(ctx, apigw, domain):
    acm = ctx.client("acm")
    cert_pem, key_pem = _self_signed_cert(domain)
    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=TAGS_KV
    )["CertificateArn"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: _retrying(
                lambda: acm.delete_certificate(CertificateArn=cert_arn),
                retries=4,
                base_delay=2.0,
                retryable=("TooManyRequestsException", "ResourceInUseException"),
            )
        )
    )
    created = _retrying(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}
            ],
            Tags=TAGS,
        )
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: apigw.delete_domain_name(DomainName=domain)))
    # routing rules require the domain's RoutingMode to enable rule evaluation
    apigw.update_domain_name(DomainName=domain, RoutingMode="ROUTING_RULE_THEN_API_MAPPING")
    return created



def _retrying(fn, *, retries=6, base_delay=3.0, retryable=("TooManyRequestsException",)):
    import time

    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] in retryable and attempt < retries - 1:
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
