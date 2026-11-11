"""routing-rule-duplicate-priority-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "routing-rule-duplicate-priority-rejected"
GROUP = "negative-classes"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRoutingRule rejects a second rule with a priority already in use on the domain,
    leaves the existing rule untouched, and a differently-prioritized rule still succeeds."""
    domain_name, cert_arn = _resolve_custom_domain_prereqs(ctx)
    apigw = ctx.client("apigatewayv2")

    apigw.create_domain_name(
        DomainName=domain_name,
        DomainNameConfigurations=[{"CertificateArn": cert_arn, "EndpointType": "REGIONAL"}],
        RoutingMode="ROUTING_RULE_ONLY",
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_domain_name(DomainName=domain_name))
    _wait_domain_available(ctx, domain_name)

    # RoutingRuleAction.InvokeApi only accepts a REST-protocol API as its target ("Invalid API
    # protocol type. Only the REST protocol type is supported." on real AWS) -- an apigatewayv2
    # HTTP API is rejected outright, so the backend under a routing rule is built with the
    # apigateway (v1/REST) service, not apigatewayv2.
    api_id = _create_minimal_rest_api(ctx)

    first = apigw.create_routing_rule(
        DomainName=domain_name,
        Priority=100,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["neg-a"]}}],
        Actions=[{"InvokeApi": {"ApiId": api_id, "Stage": "prod", "StripBasePath": True}}],
    )
    first_id = first["RoutingRuleId"]
    ctx.on_cleanup(lambda: _safe_delete_rule(apigw, domain_name, first_id))

    code, message = _error_code(
        lambda: apigw.create_routing_rule(
            DomainName=domain_name,
            Priority=100,
            Conditions=[{"MatchBasePaths": {"AnyOf": ["neg-b"]}}],
            Actions=[{"InvokeApi": {"ApiId": api_id, "Stage": "prod", "StripBasePath": True}}],
        )
    )
    # Real AWS answers this specific conflict with BadRequestException and a message naming the
    # duplicate priority value -- not the generically-plausible ConflictException.
    assert code == "BadRequestException", f"expected BadRequestException for a duplicate priority, got {code!r} ({message!r})"
    expected_message = "Trying to add rule with duplicate priority: 100"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the domain still has exactly the one original rule, unmodified.
    rules = apigw.list_routing_rules(DomainName=domain_name)["RoutingRules"]
    assert len(rules) == 1, f"expected exactly 1 routing rule after the rejected duplicate, got {len(rules)}"
    assert rules[0]["RoutingRuleId"] == first_id, (
        f"expected the surviving rule to be {first_id!r}, got {rules[0]['RoutingRuleId']!r}"
    )
    assert rules[0]["Priority"] == 100, f"expected the surviving rule's priority unchanged at 100, got {rules[0]['Priority']}"
    assert rules[0]["Conditions"] == [{"MatchBasePaths": {"AnyOf": ["neg-a"]}}], (
        f"expected the surviving rule's conditions unmodified, got {rules[0]['Conditions']!r}"
    )

    # Positive control: a rule at a different, unused priority on the same domain still succeeds.
    second = apigw.create_routing_rule(
        DomainName=domain_name,
        Priority=200,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["neg-c"]}}],
        Actions=[{"InvokeApi": {"ApiId": api_id, "Stage": "prod", "StripBasePath": True}}],
    )
    second_id = second["RoutingRuleId"]
    ctx.on_cleanup(lambda: apigw.delete_routing_rule(DomainName=domain_name, RoutingRuleId=second_id))

    rules_after = {r["RoutingRuleId"]: r for r in apigw.list_routing_rules(DomainName=domain_name)["RoutingRules"]}
    assert set(rules_after) == {first_id, second_id}, (
        f"expected exactly {{first_id, second_id}} = {{{first_id!r}, {second_id!r}}}, got {set(rules_after)!r}"
    )
    assert rules_after[second_id]["Priority"] == 200, (
        f"expected the positive-control rule's priority to be 200, got {rules_after[second_id]['Priority']}"
    )

    # Restore: the rejection is state-dependent, not an inherently-invalid input -- freeing the
    # occupied priority by deleting the rule that held it makes the identical Priority=100 call
    # that was just rejected succeed.
    apigw.delete_routing_rule(DomainName=domain_name, RoutingRuleId=first_id)
    restored = apigw.create_routing_rule(
        DomainName=domain_name,
        Priority=100,
        Conditions=[{"MatchBasePaths": {"AnyOf": ["neg-b"]}}],
        Actions=[{"InvokeApi": {"ApiId": api_id, "Stage": "prod", "StripBasePath": True}}],
    )
    restored_id = restored["RoutingRuleId"]
    ctx.on_cleanup(lambda: apigw.delete_routing_rule(DomainName=domain_name, RoutingRuleId=restored_id))

    rules_final = {r["RoutingRuleId"] for r in apigw.list_routing_rules(DomainName=domain_name)["RoutingRules"]}
    assert rules_final == {restored_id, second_id}, (
        f"expected exactly {{restored_id, second_id}} = {{{restored_id!r}, {second_id!r}}} after freeing "
        f"priority 100, got {rules_final!r}"
    )


def _create_minimal_rest_api(ctx) -> str:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-api-"), tags={"sim2real-check": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200", responseTemplates={}
    )
    apigw.create_deployment(restApiId=api_id, stageName="prod")
    return api_id


def _resolve_custom_domain_prereqs(ctx) -> tuple[str, str]:
    """The custom domain is a prerequisite of this check, not part of the contract under test —
    CreateRoutingRule/ListRoutingRules never issue a real HTTPS request to it (unlike the e2e
    siblings, which do and therefore need a DNS-validated certificate). So an ACM certificate
    IMPORTED here (self-signed, immediately ISSUED, no DNS control needed) is a real, valid
    certificate ARN on real AWS, not a fabricated one -- CreateDomainName accepts it."""
    domain_name = f"{_dns_label(ctx.unique_name('sim2real-behav-dom-'))}.example.com"
    require_tools("openssl")
    acm = ctx.client("acm")
    cert_pem, key_pem = _generate_self_signed(domain_name)
    cert_arn = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _safe_delete_cert(acm, cert_arn))
    return domain_name, cert_arn


def _dns_label(name: str) -> str:
    label = "".join(c if c.isalnum() else "-" for c in name.lower())
    return label.strip("-") or "sim2real"


def _generate_self_signed(common_name: str) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        crt_path = os.path.join(d, "cert.pem")
        _run(["openssl", "genrsa", "-out", key_path, "2048"])
        _run(
            [
                "openssl", "req", "-x509", "-new", "-nodes", "-key", key_path,
                "-sha256", "-days", "30", "-subj", f"/CN={common_name}", "-out", crt_path,
            ]
        )
        with open(crt_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    return cert_pem, key_pem


def _run(cmd: list) -> None:
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.decode(errors='replace')}")


def _safe_delete_cert(acm, cert_arn: str) -> None:
    try:
        acm.delete_certificate(CertificateArn=cert_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_rule(apigw, domain_name: str, rule_id: str) -> None:
    """The run body already deletes and replaces this rule id as part of its restore leg;
    this cleanup is only a safety net for a run that raised before reaching that point."""
    try:
        apigw.delete_routing_rule(DomainName=domain_name, RoutingRuleId=rule_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_domain_available(ctx, domain_name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    apigw = ctx.client("apigatewayv2")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cfg = apigw.get_domain_name(DomainName=domain_name)["DomainNameConfigurations"][0]
        last_status = cfg.get("DomainNameStatus")
        if last_status == "AVAILABLE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"domain name never reached AVAILABLE (last status={last_status})")


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its (code, message). An unexpected SUCCESS raises rather than returning a
    falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected CreateRoutingRule to reject the duplicate priority, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
