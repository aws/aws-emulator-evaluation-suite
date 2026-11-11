"""routing-rule-priority-numeric-precision-preserved."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "routing-rule-priority-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A routing rule created with a specific integer Priority returns the exact same
    numeric value (same type, no float coercion or truncation) via GetRoutingRule."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    domain_name = f"{ctx.unique_name('sim2real-rr-')}.example.com"
    cert_arn = _import_self_signed_cert(ctx, domain_name)
    apigw = ctx.client("apigatewayv2")
    apigw.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
        RoutingMode="ROUTING_RULE_ONLY",
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_domain_name(DomainName=domain_name)))

    # RoutingRule InvokeApi actions only support REST APIs (API Gateway v1), not
    # HTTP/WebSocket APIs created via apigatewayv2 CreateApi ("Invalid API protocol
    # type. Only the REST protocol type is supported" is returned otherwise).
    apigw_v1 = ctx.client("apigateway")
    api_id = apigw_v1.create_rest_api(
        name=ctx.unique_name("sim2real-restapi-"), tags={"sim2real-check": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw_v1.delete_rest_api(restApiId=api_id)))
    root_id = apigw_v1.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw_v1.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw_v1.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw_v1.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw_v1.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    stage_name = "prod"
    apigw_v1.create_deployment(restApiId=api_id, stageName=stage_name)
    ctx.on_cleanup(lambda: _safe(lambda: apigw_v1.delete_stage(restApiId=api_id, stageName=stage_name)))

    priority = 250
    created = apigw.create_routing_rule(
        DomainName=domain_name,
        Priority=priority,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["priority-test"]}}],
        Actions=[{"InvokeApi": {"ApiId": api_id, "Stage": stage_name}}],
    )
    routing_rule_id = created["RoutingRuleId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: apigw.delete_routing_rule(DomainName=domain_name, RoutingRuleId=routing_rule_id)
        )
    )
    assert created["Priority"] == priority, (priority, created["Priority"])
    assert isinstance(created["Priority"], int), type(created["Priority"])

    fetched = apigw.get_routing_rule(DomainName=domain_name, RoutingRuleId=routing_rule_id)
    assert fetched["Priority"] == priority, fetched["Priority"]
    assert isinstance(fetched["Priority"], int), type(fetched["Priority"])


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


def _generate_self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        cert_path = Path(d) / "cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "2", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        return cert_path.read_bytes(), key_path.read_bytes()


def _import_self_signed_cert(ctx, common_name: str) -> str:
    acm = ctx.client("acm")
    cert_pem, key_pem = _generate_self_signed_cert(common_name)
    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
    return cert_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
