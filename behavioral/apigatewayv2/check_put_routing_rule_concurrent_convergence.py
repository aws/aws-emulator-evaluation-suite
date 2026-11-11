"""put-routing-rule-concurrent-convergence."""
from __future__ import annotations

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-routing-rule-concurrent-convergence"
GROUP = "concurrency"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutRoutingRule overwrites of the same rule converge to one writer's full
    definition, never a mix of both, and the rule stays readable and mutable afterward."""
    apigw = ctx.client("apigatewayv2")

    # Routing rules are supported only for REST (v1) APIs, not HTTP APIs.
    stage_name = "test"
    api_id = _create_deployed_rest_api(ctx, "sim2real-behav-rrapi-", stage_name)

    domain = _domain_name(ctx, "sim2real-behav-rrconc")
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

    actions = [{"InvokeApi": {"ApiId": api_id, "Stage": stage_name, "StripBasePath": True}}]
    conditions_initial = [{"MatchBasePaths": {"AnyOf": ["initial"]}}]

    rule = _retry_throttled(
        lambda: apigw.create_routing_rule(
            DomainName=domain, Priority=100, Conditions=conditions_initial, Actions=actions
        )
    )
    rule_id = rule["RoutingRuleId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: apigw.delete_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
        )
    )

    conditions_a = [{"MatchBasePaths": {"AnyOf": ["alpha"]}}]
    conditions_b = [{"MatchBasePaths": {"AnyOf": ["beta"]}}]

    def _overwrite(priority, conditions):
        return _retry_throttled(
            lambda: apigw.put_routing_rule(
                DomainName=domain,
                RoutingRuleId=rule_id,
                Priority=priority,
                Conditions=conditions,
                Actions=actions,
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_overwrite, 100, conditions_a)
        fut_b = pool.submit(_overwrite, 200, conditions_b)
        outcome_a = _outcome(fut_a)
        outcome_b = _outcome(fut_b)

    successes = [o for o in (outcome_a, outcome_b) if o[0] == "ok"]
    assert len(successes) >= 1, f"expected at least one writer to succeed, got {(outcome_a, outcome_b)!r}"

    # Effect present but consistent (no split-brain): the rule's final Priority and
    # Conditions belong to exactly one of the two attempted writes, never a mix of both.
    final = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
    final_base_path = final["Conditions"][0]["MatchBasePaths"]["AnyOf"][0]
    if final["Priority"] == 100:
        assert final_base_path == "alpha", f"mixed/corrupted state: {final!r}"
    elif final["Priority"] == 200:
        assert final_base_path == "beta", f"mixed/corrupted state: {final!r}"
    else:
        raise AssertionError(f"final Priority {final['Priority']!r} matches neither writer: {final!r}")

    # Positive control: the rule remains normally mutable afterward.
    _retry_throttled(
        lambda: apigw.put_routing_rule(
            DomainName=domain,
            RoutingRuleId=rule_id,
            Priority=300,
            Conditions=[{"MatchBasePaths": {"AnyOf": ["final"]}}],
            Actions=actions,
        )
    )
    control_read = apigw.get_routing_rule(DomainName=domain, RoutingRuleId=rule_id)
    assert control_read["Priority"] == 300, (
        f"expected Priority 300 after positive-control write, got {control_read!r}"
    )
    assert control_read["Conditions"][0]["MatchBasePaths"]["AnyOf"][0] == "final", (
        f"expected condition 'final' after positive-control write, got {control_read!r}"
    )




if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


def _domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    label = "".join(c if c.isalnum() or c == "-" else "-" for c in raw.lower()).strip("-")
    return f"{label}.example.com"


def _create_deployed_rest_api(ctx, prefix: str, stage_name: str) -> str:
    """Create a minimal REST (v1) API with a MOCK method, deploy it, and return its ApiId."""
    apigw_v1 = ctx.client("apigateway")
    rest_api_id = apigw_v1.create_rest_api(
        name=ctx.unique_name(prefix), tags={"sim2real": CHECK}
    )["id"]
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
        Certificate=cert_bytes,
        PrivateKey=key_bytes,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
    return cert_arn


def _outcome(future):
    try:
        future.result()
        return ("ok", None)
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"])


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
