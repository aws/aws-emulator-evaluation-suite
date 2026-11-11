"""create-routing-rule-missing-condition-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "create-routing-rule-missing-condition-rejected"
GROUP = "negative-classes"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoutingRule with a condition entry that carries no actual match clause (no
    matchBasePaths/matchHeaders) is rejected with BadRequestException and no rule is created;
    a routing rule with a real condition still gets created."""
    apigwv2 = ctx.client("apigatewayv2")
    domain_name = _create_domain_name(ctx)
    api_id = _create_rest_api_with_stage(ctx, "dev")
    action = [{"InvokeApi": {"ApiId": api_id, "Stage": "dev"}}]

    code, message = _error_of(
        lambda: apigwv2.create_routing_rule(
            DomainName=domain_name, Priority=100, Conditions=[{}], Actions=action
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        "Invalid conditions for RoutingRule. Each condition can only be either matchBasePaths or matchHeaders."
    ), f"BadRequestException message {message!r}"

    listing = apigwv2.list_routing_rules(DomainName=domain_name)["RoutingRules"]
    assert not any(r["Priority"] == 100 for r in listing), (
        f"a rule with Priority=100 should not have been created, saw {listing!r}"
    )

    # positive control: a routing rule with a real match condition is created successfully.
    created = apigwv2.create_routing_rule(
        DomainName=domain_name,
        Priority=200,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["positive"]}}],
        Actions=action,
    )
    rule_id = created["RoutingRuleId"]
    ctx.on_cleanup(lambda: apigwv2.delete_routing_rule(DomainName=domain_name, RoutingRuleId=rule_id))
    fetched = apigwv2.get_routing_rule(DomainName=domain_name, RoutingRuleId=rule_id)
    assert fetched["Priority"] == 200, f"expected Priority=200, got {fetched.get('Priority')!r}"


def _error_of(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _import_self_signed_cert(ctx, common_name):
    acm = ctx.client("acm")
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    return cert_arn


def _create_domain_name(ctx):
    apigwv2 = ctx.client("apigatewayv2")
    label = ctx.unique_name("sim2real-apigwv2-").lower().replace("_", "-")
    domain_name = f"{label}.example.com"
    cert_arn = _import_self_signed_cert(ctx, domain_name)
    apigwv2.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[
            {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
        ],
        RoutingMode="ROUTING_RULE_THEN_API_MAPPING",
    )
    ctx.on_cleanup(lambda: apigwv2.delete_domain_name(DomainName=domain_name))
    return domain_name


def _create_rest_api_with_stage(ctx, stage_name):
    # RoutingRule actions invoke a REST API (created via the apigateway v1 API) -- an
    # apigatewayv2 HTTP API is rejected with "Invalid API protocol type. Only the REST
    # protocol type is supported."
    apigw = ctx.client("apigateway")
    resp = apigw.create_rest_api(name=ctx.unique_name("sim2real-restapi-"))
    api_id = resp["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    ctx.on_cleanup(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
