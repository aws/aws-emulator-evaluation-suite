"""routing-rule-lifecycle."""
from __future__ import annotations

import os
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "routing-rule-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoutingRule is gettable, PutRoutingRule overwrites the definition, DeleteRoutingRule -> NotFoundException,
    and a mutation on the dead id fails the same way."""
    apigw = ctx.client("apigatewayv2")

    # Routing rules are supported only for REST (v1) APIs, not HTTP APIs.
    stage_name = "prod"
    api_id = _create_deployed_rest_api(ctx, "sim2real-rr-restapi-", stage_name)

    domain = _domain_name(ctx, "sim2real-rr-dn")
    cert_arn = _self_signed_cert_arn(ctx, domain)
    _retry_throttled(
        lambda: apigw.create_domain_name(
            DomainName=domain,
            DomainNameConfigurations=[
                {"CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2"}
            ],
            RoutingMode="ROUTING_RULE_THEN_API_MAPPING",
            Tags=TAGS,
        )
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_domain_name(DomainName=domain)))

    action = [{"InvokeApi": {"ApiId": api_id, "Stage": stage_name, "StripBasePath": True}}]

    created = apigw.create_routing_rule(
        DomainName=domain,
        Priority=10,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["foo"]}}],
        Actions=action,
    )
    rule_id = created["RoutingRuleId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
        )
    )
    assert created["Conditions"][0]["MatchBasePaths"]["AnyOf"] == ["foo"], (
        f"expected CreateRoutingRule response to echo conditions ['foo'], got {created['Conditions']!r}"
    )

    got = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
    assert got["Conditions"][0]["MatchBasePaths"]["AnyOf"] == ["foo"], (
        f"expected independent read to reflect conditions ['foo'], got {got['Conditions']!r}"
    )
    assert got["Priority"] == 10, f"expected priority 10, got {got['Priority']!r}"

    overwritten = apigw.put_routing_rule(
        DomainName=domain,
        RoutingRuleId=rule_id,
        Priority=10,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["bar"]}}],
        Actions=action,
    )
    assert overwritten["Conditions"][0]["MatchBasePaths"]["AnyOf"] == ["bar"], (
        f"expected PutRoutingRule response to echo overwritten conditions ['bar'], got {overwritten['Conditions']!r}"
    )

    got2 = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
    assert got2["Conditions"][0]["MatchBasePaths"]["AnyOf"] == ["bar"], (
        f"expected independent read after PutRoutingRule to reflect ['bar'], got {got2['Conditions']!r}"
    )

    apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
    code = _error_of(lambda: apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id))
    assert code == ("NotFoundException", "Unable to find RoutingRule."), (
        f"expected NotFoundException reading a deleted routing rule, got {code!r}"
    )

    mutate_code = _error_of(
        lambda: apigw.put_routing_rule(
            DomainName=domain,
            RoutingRuleId=rule_id,
            Priority=10,
            Conditions=[{"MatchBasePaths": {"AnyOf": ["baz"]}}],
            Actions=action,
        )
    )
    assert mutate_code == ("NotFoundException", "Unable to find RoutingRule."), (
        f"expected NotFoundException mutating a deleted routing rule, got {mutate_code!r}"
    )


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _create_deployed_rest_api(ctx, prefix: str, stage_name: str) -> str:
    """Create a minimal REST (v1) API with a MOCK method, deploy it, and return its ApiId."""
    apigw_v1 = ctx.client("apigateway")
    rest_api_id = apigw_v1.create_rest_api(name=ctx.unique_name(prefix), tags=TAGS)["id"]
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
    acm = ctx.client("acm")
    require_tools("openssl")
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
    resp = acm.import_certificate(Certificate=cert_bytes, PrivateKey=key_bytes, Tags=TAGS_KV)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying(acm, cert_arn))
    return cert_arn


def _delete_cert_retrying(acm, cert_arn: str) -> None:
    """ACM keeps a certificate's InUseBy association for a beat after the domain name that
    referenced it is gone, so an immediate delete can 409 with ResourceInUseException."""
    import time

    for attempt in range(5):
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and attempt < 4:
                time.sleep(3.0 * (attempt + 1))
                continue
            raise


def _error_of(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    import time

    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "LimitExceededException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, exc.response["Error"]["Message"]
        else:
            raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")
    raise AssertionError("exhausted retries on throttling without a definitive response")


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
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
