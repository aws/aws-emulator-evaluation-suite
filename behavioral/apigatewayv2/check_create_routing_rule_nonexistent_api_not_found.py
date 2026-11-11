"""create-routing-rule-nonexistent-api-not-found."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-routing-rule-nonexistent-api-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoutingRule on a nonexistent domain with a real deployed REST API target fails
    NotFoundException and persists nothing; the same call against an existing domain succeeds."""
    apigw = ctx.client("apigatewayv2")

    # The target API is real so the missing domain is the only broken variable.
    stage_name = "prod"
    api_id = _create_deployed_rest_api(ctx, "sim2real-behav-rrapi-", stage_name)

    missing_domain = _domain_name(ctx, "sim2real-behav-rrmiss")
    conditions = [{"MatchBasePaths": {"AnyOf": ["foo"]}}]
    actions = [{"InvokeApi": {"ApiId": api_id, "Stage": stage_name, "StripBasePath": True}}]

    code, message = _error_code(
        lambda: apigw.create_routing_rule(
            DomainName=missing_domain, Priority=10, Conditions=conditions, Actions=actions
        )
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException, got {code!r}: {message!r}"
    )
    assert message == "Invalid domain name identifier specified", (
        f"unexpected NotFoundException message: {message!r}"
    )

    # Effect absent: the domain still does not exist, and listing its rules 404s too.
    still_missing, list_message = _error_code(lambda: apigw.list_routing_rules(DomainName=missing_domain))
    assert still_missing == "NotFoundException", f"got {still_missing!r}: {list_message!r}"
    assert list_message == "Invalid domain name identifier specified", (
        f"unexpected NotFoundException message: {list_message!r}"
    )

    # Positive control: the same shape of call against a real domain + the same real REST API succeeds.
    domain = _domain_name(ctx, "sim2real-behav-rrreal")
    cert_arn = _self_signed_cert_arn(ctx, domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
            RoutingMode="ROUTING_RULE_THEN_API_MAPPING",
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=domain)))

    real_actions = [{"InvokeApi": {"ApiId": api_id, "Stage": stage_name, "StripBasePath": True}}]
    rule = apigw.create_routing_rule(
        DomainName=domain, Priority=10, Conditions=conditions, Actions=real_actions
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=rule["RoutingRuleId"])
        )
    )
    fetched = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule["RoutingRuleId"])
    assert fetched["Priority"] == 10


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _create_deployed_rest_api(ctx, prefix: str, stage_name: str) -> str:
    """Create a minimal REST (v1) API with a MOCK method, deploy it, and return its ApiId."""
    apigw_v1 = ctx.client("apigateway")
    rest_api_id = apigw_v1.create_rest_api(name=ctx.unique_name(prefix), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw_v1.delete_rest_api(restApiId=rest_api_id)))

    root_id = apigw_v1.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    apigw_v1.put_method(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigw_v1.put_integration(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw_v1.put_method_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw_v1.put_integration_response(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigw_v1.create_deployment(restApiId=rest_api_id, stageName=stage_name)
    return rest_api_id


def _self_signed_cert_arn(ctx, domain: str) -> str:
    """Generate a throwaway self-signed certificate via openssl and import it into ACM."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "30", "-nodes", "-subj", f"/CN={domain}",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
        with open(key_path, "rb") as f:
            key_bytes = f.read()
    resp = acm.import_certificate(
        Certificate=cert_bytes, PrivateKey=key_bytes, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
    return cert_arn


def _error_code(fn):
    import time

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, message
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    raise AssertionError("unreachable")


def _retry_throttled(fn, *, attempts: int = 6, base_delay: float = 3.0):
    import time

    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < attempts - 1:
                last_exc = exc
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last_exc


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
