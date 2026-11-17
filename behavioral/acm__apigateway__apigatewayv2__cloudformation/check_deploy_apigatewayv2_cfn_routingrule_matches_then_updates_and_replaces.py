"""deploy-apigatewayv2-cfn-routingrule-matches-then-updates-and-replaces."""
from __future__ import annotations

import datetime
import json
import socket
import ssl
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-routingrule-matches-then-updates-and-replaces"
GROUP = "deploy"
SERVICES = ["acm", "apigateway", "apigatewayv2", "cloudformation"]

_THROTTLE = ("TooManyRequestsException", "Too Many Requests")
_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _error_pair(fn) -> tuple[str, str]:
    """The ``(Code, Message)`` ``fn`` raises; an unexpected success raises too, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it returned {result!r}")


def _retry_throttled(fn, attempts: int = 8):
    """Call ``fn()``, retrying only ApiGatewayV2's own control-plane throttle."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _THROTTLE or attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.25 * (2 ** attempt)))


def _poll_until(observe, ok, *, timeout_s: float, interval_s: float, description: str):
    """Re-run ``observe()`` until ``ok(value)`` holds; raise naming the last value on deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = observe()
        if ok(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"{description}: last observed {last!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _poll_route(observe, ok, *, timeout_s: float, interval_s: float, description: str):
    """Re-run ``observe()`` until ``ok(result)`` holds, past a connection error (DNS/TLS not yet
    up) or a response an unconverged edge node still answers with (the regional custom domain's
    load balancer propagates per node, not atomically).
    """
    deadline = time.monotonic() + timeout_s
    last = "none"
    while True:
        try:
            result = observe()
        except (OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            if ok(result):
                return result
            last = result
        if time.monotonic() > deadline:
            raise AssertionError(f"{description}: last observed {last!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _served_200(expected: str):
    def ok(result) -> bool:
        status, body = result
        if status != 200:
            return False
        try:
            return json.loads(body) == {"served": expected}
        except ValueError:
            return False
    return ok


def _is_403(result) -> bool:
    status, _body = result
    return status == 403


def _crypto():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    return x509, hashes, serialization, rsa, NameOID


def _self_issued(subject_cn: str, *, is_ca: bool, issuer_name=None, issuer_key=None, sans=None):
    """A certificate for ``subject_cn``: self-signed when ``issuer_key`` is ``None``, else signed
    by it. Returns ``(x509.Certificate, private_key)``.
    """
    x509, hashes, _serialization, rsa, NameOID = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = issuer_name if issuer_name is not None else subject
    signing_key = issuer_key if issuer_key is not None else key
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(signing_key, hashes.SHA256())
    return cert, key


def _pem_cert(cert) -> bytes:
    _x509, _hashes, serialization, _rsa, _n = _crypto()
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key) -> bytes:
    _x509, _hashes, serialization, _rsa, _n = _crypto()
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _root_and_leaf_pem(domain: str) -> tuple[bytes, bytes, bytes]:
    """A root CA and a leaf it signs for ``domain``; ``(leaf_pem, leaf_key_pem, root_pem)``."""
    root_cert, root_key = _self_issued(f"root-{domain}", is_ca=True)
    leaf_cert, leaf_key = _self_issued(
        domain, is_ca=False, issuer_name=root_cert.subject, issuer_key=root_key, sans=[domain]
    )
    return _pem_cert(leaf_cert), _pem_key(leaf_key), _pem_cert(root_cert)


def _import_cert(acm, domain: str) -> tuple[str, bytes]:
    """Import a root-signed leaf for ``domain``; wait for ACM to report it ISSUED.

    Returns the certificate's ARN and the root CA's PEM, which is what a client must trust. No
    teardown is registered here: AWS releases a regional custom domain's load-balancer binding to
    an imported certificate on its own schedule, well past this domain's own deletion, so a
    registered delete could not be made to raise only on a genuine failure (cleanup-and-leaks.md,
    "register nothing and declare it"). The caller reports the ARN as a leftover instead.
    """
    leaf_pem, leaf_key_pem, root_pem = _root_and_leaf_pem(domain)
    arn = _retry_throttled(lambda: acm.import_certificate(
        Certificate=leaf_pem, PrivateKey=leaf_key_pem, CertificateChain=root_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"],
        lambda status: status == "ISSUED",
        timeout_s=90, interval_s=3,
        description="the imported leaf reaching ACM status ISSUED",
    )
    return arn, root_pem


def _teardown_domain(apigwv2, domain: str) -> None:
    try:
        apigwv2.delete_domain_name(DomainName=domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_domain(ctx, apigwv2, domain: str, *, cert_arn: str):
    """CreateDomainName always needs exactly one DomainNameConfigurations entry: a REGIONAL
    domain the rule only targets, never dialed, still needs its own certificate.
    """
    created = _retry_throttled(lambda: apigwv2.create_domain_name(
        DomainName=domain, RoutingMode="ROUTING_RULE_ONLY", Tags={"sim2real": CHECK},
        DomainNameConfigurations=[{
            "CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2",
        }],
    ))
    ctx.on_cleanup(lambda: _teardown_domain(apigwv2, domain))
    return created


def _await_domain_available(apigwv2, domain: str) -> str:
    """Poll GetDomainName to AVAILABLE; return the regional ApiGatewayDomainName to dial."""
    cfg = _poll_until(
        lambda: _retry_throttled(
            lambda: apigwv2.get_domain_name(DomainName=domain))["DomainNameConfigurations"][0],
        lambda cfg: cfg["DomainNameStatus"] == "AVAILABLE",
        timeout_s=300, interval_s=10,
        description="the regional custom domain reaching DomainNameStatus=AVAILABLE",
    )
    host = cfg.get("ApiGatewayDomainName")
    assert host, f"an AVAILABLE regional domain must publish an ApiGatewayDomainName; got {cfg!r}"
    return host


def _invoke_policy(ctx) -> str:
    """A resource policy admitting execute-api:Invoke only from the runner's own egress."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": "execute-api:/*",
            "Condition": {"IpAddress": {"aws:SourceIp": ctx.ingress_cidrs()}},
        }],
    })


def _root_resource_id(ag, api_id: str) -> str:
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"restApiId={api_id!r} has no root ('/') resource")


def _delete_rest_api(ag, api_id: str, *, budget_s: float = 300.0) -> None:
    """DeleteRestApi is quota'd per account; retry its own throttle within one deadline."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "NotFoundException":
                return
            if (err.get("Code"), err.get("Message")) != _THROTTLE or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _build_two_route_rest_api(ctx, ag) -> str:
    """A REGIONAL REST API with MOCK GET /widgets and /gadgets, each echoing which one answered."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-rr-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        policy=_invoke_policy(ctx),
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))
    root = _root_resource_id(ag, api_id)
    for leaf in ("widgets", "gadgets"):
        resource_id = _retry_throttled(lambda leaf=leaf: ag.create_resource(
            restApiId=api_id, parentId=root, pathPart=leaf))["id"]
        _retry_throttled(lambda resource_id=resource_id: ag.put_method(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"))
        _retry_throttled(lambda resource_id=resource_id: ag.put_integration(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="MOCK",
            requestTemplates={"application/json": '{"statusCode": 200}'}))
        _retry_throttled(lambda resource_id=resource_id: ag.put_method_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"))
        _retry_throttled(lambda resource_id=resource_id, leaf=leaf: ag.put_integration_response(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200",
            selectionPattern="", responseTemplates={"application/json": json.dumps({"served": leaf})}))
    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="prod", deploymentId=deployment_id,
        tags={"sim2real": CHECK}))
    return api_id


def _tls_get(ctx, trust_pem: bytes, gateway_host: str, domain: str, path: str) -> tuple[int, str]:
    """A raw HTTP/1.1 GET over TLS to ``gateway_host``, SNI and Host set to the custom domain."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=trust_pem.decode("ascii"))
    host, port = ctx.endpoint_host(gateway_host, 443)
    with socket.create_connection((host, port), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            tls.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode("ascii")
            )
            chunks = []
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
    head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
    return int(status_line.split(" ", 2)[1]), body.decode(errors="replace")


def _wait_stack(cf, stack_id: str, terminal=_STACK_TERMINAL, timeout_s: float = 300.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(3)


def _stack_outputs(cf, stack_id: str) -> dict:
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _physical_id(cf, stack_id: str, logical_id: str) -> str:
    return cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _delete_stack(cf, stack_id: str, *, timeout_s: float = 300.0) -> None:
    try:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in exc.response["Error"].get("Message", ""):
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    final = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s)
    assert final == "DELETE_COMPLETE", f"stack {stack_id} delete ended {final!r}"


def _template(domain_arn: str, priority: int, base_path: str, api_id: str, stage: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RoutingRule": {
                "Type": "AWS::ApiGatewayV2::RoutingRule",
                "Properties": {
                    "DomainNameArn": domain_arn,
                    "Priority": priority,
                    "Conditions": [{"MatchBasePaths": {"AnyOf": [base_path]}}],
                    "Actions": [{"InvokeApi": {"ApiId": api_id, "Stage": stage}}],
                },
            },
        },
        "Outputs": {
            "RoutingRuleId": {"Value": {"Fn::GetAtt": ["RoutingRule", "RoutingRuleId"]}},
            "RoutingRuleArn": {"Value": {"Fn::GetAtt": ["RoutingRule", "RoutingRuleArn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CloudFormation ApiGatewayV2 RoutingRule forwards a matching path to its REST API stage
    and refuses a non-matching one; changing Conditions updates the rule in place, and changing
    DomainNameArn replaces it onto the new domain.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-routingrule.html
    """
    acm = ctx.client("acm")
    apigwv2 = ctx.client("apigatewayv2")
    ag = ctx.client("apigateway")
    cfn = ctx.client("cloudformation")

    domain_a = f"{ctx.unique_name('sim2real-xsvc-rra-')}.example.com"
    domain_b = f"{ctx.unique_name('sim2real-xsvc-rrb-')}.example.com"
    domain_a_arn = f"arn:aws:apigateway:{ctx.region}::/domainnames/{domain_a}"
    domain_b_arn = f"arn:aws:apigateway:{ctx.region}::/domainnames/{domain_b}"

    cert_arn, trust_pem = _import_cert(acm, domain_a)
    _create_domain(ctx, apigwv2, domain_a, cert_arn=cert_arn)
    gateway_host = _await_domain_available(apigwv2, domain_a)

    api_id = _build_two_route_rest_api(ctx, ag)

    stack_name = ctx.unique_name("sim2real-xsvc-rr-stk-")
    created: dict[str, str] = {}
    ctx.on_cleanup(lambda: _delete_stack(cfn, created["StackId"]) if created.get("StackId") else None)
    created["StackId"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(domain_a_arn, 100, "widgets", api_id, "prod"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    stack_id = created["StackId"]

    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"the create ended {status!r}, expected CREATE_COMPLETE"

    outputs = _stack_outputs(cfn, stack_id)
    rule_id, rule_arn = outputs["RoutingRuleId"], outputs["RoutingRuleArn"]

    got = apigwv2.get_routing_rule(DomainName=domain_a, RoutingRuleId=rule_id)
    assert got["Priority"] == 100, f"GetRoutingRule reports Priority={got['Priority']!r}, expected 100"
    assert got["Conditions"] == [{"MatchBasePaths": {"AnyOf": ["widgets"]}}], (
        f"GetRoutingRule reports Conditions={got['Conditions']!r}, expected the templated base path"
    )
    invoke = got["Actions"][0]["InvokeApi"]
    assert (invoke["ApiId"], invoke["Stage"]) == (api_id, "prod"), (
        f"GetRoutingRule reports the action targets {invoke!r}, expected api {api_id!r} stage 'prod'"
    )

    _poll_route(
        lambda: _tls_get(ctx, trust_pem, gateway_host, domain_a, "/widgets"),
        _served_200("widgets"),
        timeout_s=600, interval_s=10,
        description="the custom domain forwarding /widgets through the routing rule",
    )
    _poll_route(
        lambda: _tls_get(ctx, trust_pem, gateway_host, domain_a, "/gadgets"),
        _is_403,
        timeout_s=120, interval_s=5,
        description="GET /gadgets, matching no condition on this domain, being refused",
    )

    # In-place update: Priority and Conditions are not createOnly, so the same rule is reused.
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_template(domain_a_arn, 200, "gadgets", api_id, "prod")
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"the in-place update ended {status!r}"

    after_update_arn = _physical_id(cfn, stack_id, "RoutingRule")
    assert after_update_arn == rule_arn, (
        f"changing Priority and Conditions must update the SAME rule in place; the physical id "
        f"moved from {rule_arn!r} to {after_update_arn!r}"
    )
    got2 = apigwv2.get_routing_rule(DomainName=domain_a, RoutingRuleId=rule_id)
    assert got2["Priority"] == 200, f"after the update, Priority={got2['Priority']!r}, expected 200"
    assert got2["Conditions"] == [{"MatchBasePaths": {"AnyOf": ["gadgets"]}}], (
        f"after the update, Conditions={got2['Conditions']!r}, expected the new base path"
    )

    _poll_route(
        lambda: _tls_get(ctx, trust_pem, gateway_host, domain_a, "/gadgets"),
        _served_200("gadgets"),
        timeout_s=300, interval_s=10,
        description="the routing rule, re-pointed to /gadgets, forwarding it after the update",
    )
    _poll_route(
        lambda: _tls_get(ctx, trust_pem, gateway_host, domain_a, "/widgets"),
        _is_403,
        timeout_s=300, interval_s=10,
        description="GET /widgets, whose condition the update dropped, being refused",
    )

    # Replacement: DomainNameArn is createOnly, so changing it must swap the physical resource.
    cert_arn_b, _trust_pem_b = _import_cert(acm, domain_b)
    _create_domain(ctx, apigwv2, domain_b, cert_arn=cert_arn_b)
    cfn.update_stack(
        StackName=stack_id, TemplateBody=_template(domain_b_arn, 200, "gadgets", api_id, "prod")
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"the DomainNameArn replacement ended {status!r}"

    after_replace_arn = _physical_id(cfn, stack_id, "RoutingRule")
    assert after_replace_arn != rule_arn, (
        f"changing the create-only DomainNameArn must replace the rule; the physical id is "
        f"still {after_replace_arn!r}"
    )
    new_id = _stack_outputs(cfn, stack_id)["RoutingRuleId"]
    assert new_id != rule_id, f"the replacement kept the superseded RoutingRuleId {new_id!r}"

    gone = _error_pair(lambda: apigwv2.get_routing_rule(DomainName=domain_a, RoutingRuleId=rule_id))
    assert gone == ("NotFoundException", "Unable to find RoutingRule."), (
        f"the superseded rule must be gone from its old domain; GetRoutingRule returned {gone!r}"
    )
    moved = apigwv2.get_routing_rule(DomainName=domain_b, RoutingRuleId=new_id)
    assert (moved["Priority"], moved["Conditions"]) == (
        200, [{"MatchBasePaths": {"AnyOf": ["gadgets"]}}]
    ), f"the replacement rule on the new domain reports {moved!r}"

    # Delete: the rule leaves nothing behind on the domain it last belonged to.
    _delete_stack(cfn, stack_id)
    deleted = _error_pair(
        lambda: apigwv2.get_routing_rule(DomainName=domain_b, RoutingRuleId=new_id)
    )
    assert deleted == ("NotFoundException", "Unable to find RoutingRule."), (
        f"after the stack delete, GetRoutingRule for the removed rule returned {deleted!r}"
    )
    remaining = apigwv2.list_routing_rules(DomainName=domain_b).get("RoutingRules", [])
    assert remaining == [], (
        f"ListRoutingRules on the target domain still reports {remaining!r} after the stack delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
