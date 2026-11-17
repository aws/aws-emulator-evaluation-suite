"""deploy-apigatewayv2-cfn-routingrule-priority-over-maximum-rejected."""
from __future__ import annotations

import datetime
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-cfn-routingrule-priority-over-maximum-rejected"
GROUP = "deploy"
SERVICES = ["acm", "apigateway", "apigatewayv2", "cloudformation"]

_THROTTLE = ("TooManyRequestsException", "Too Many Requests")
_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
})


def _retry_throttled(fn, attempts: int = 8):
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _THROTTLE or attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.25 * (2 ** attempt)))


def _poll_until(observe, ok, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = observe()
        if ok(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"{description}: last observed {last!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _crypto():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    return x509, hashes, serialization, rsa, NameOID


def _self_signed_pem(domain: str) -> tuple[bytes, bytes]:
    """A self-signed, CA:true leaf naming ``domain``, importable into ACM with no chain."""
    x509, hashes, serialization, rsa, NameOID = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return cert_pem, key_pem


def _import_cert(acm, domain: str) -> str:
    """Import a self-signed leaf for ``domain``; wait for ACM to report it ISSUED.

    No teardown is registered here: AWS releases a regional custom domain's load-balancer
    binding to an imported certificate on its own schedule, well past the domain's own deletion
    (cleanup-and-leaks.md, "register nothing and declare it").
    """
    cert_pem, key_pem = _self_signed_pem(domain)
    arn = _retry_throttled(lambda: acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["CertificateArn"]
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"],
        lambda status: status == "ISSUED",
        timeout_s=90, interval_s=3,
        description="the imported leaf reaching ACM status ISSUED",
    )
    return arn


def _teardown_domain(apigwv2, domain: str) -> None:
    try:
        apigwv2.delete_domain_name(DomainName=domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_domain(ctx, apigwv2, domain: str, cert_arn: str):
    created = _retry_throttled(lambda: apigwv2.create_domain_name(
        DomainName=domain, RoutingMode="ROUTING_RULE_ONLY", Tags={"sim2real": CHECK},
        DomainNameConfigurations=[{
            "CertificateArn": cert_arn, "EndpointType": "REGIONAL", "SecurityPolicy": "TLS_1_2",
        }],
    ))
    ctx.on_cleanup(lambda: _teardown_domain(apigwv2, domain))
    return created


def _delete_rest_api(ag, api_id: str, *, budget_s: float = 300.0) -> None:
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


def _root_resource_id(ag, api_id: str) -> str:
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise AssertionError(f"restApiId={api_id!r} has no root ('/') resource")


def _build_rest_api(ctx, ag) -> str:
    """A REGIONAL REST API with a deployed stage: a routing rule's Action target only, never
    invoked by this check.
    """
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-xsvc-rrp-api-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))
    root = _root_resource_id(ag, api_id)
    _retry_throttled(lambda: ag.put_method(
        restApiId=api_id, resourceId=root, httpMethod="GET", authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=root, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(
        restApiId=api_id, resourceId=root, httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=root, httpMethod="GET", statusCode="200", selectionPattern=""))
    deployment_id = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id))["id"]
    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="prod", deploymentId=deployment_id, tags={"sim2real": CHECK}))
    return api_id


def _wait_stack(cf, stack_id: str, terminal=_STACK_TERMINAL, timeout_s: float = 300.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(3)


_HANDLER_MESSAGE = re.compile(r'^Resource handler returned message: "(.*?) \(Service: ')


def _handler_message(reason: str) -> str:
    """The ApiGatewayV2 API's own message inside CloudFormation's resource-handler wrapper,
    which otherwise carries a fresh request id on every call.
    """
    match = _HANDLER_MESSAGE.match(reason)
    assert match, f"not a resource-handler-wrapped failure reason: {reason!r}"
    return match.group(1)


def _stack_events(cf, stack_id: str) -> list[dict]:
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]][::-1]


def _delete_stack(cf, stack_id: str, *, timeout_s: float = 300.0) -> None:
    try:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in exc.response["Error"].get("Message", ""):
            return
        raise
    if status in ("DELETE_COMPLETE",):
        return
    cf.delete_stack(StackName=stack_id)
    final = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s)
    assert final == "DELETE_COMPLETE", f"stack {stack_id} delete ended {final!r}"


def _template(domain_arn: str, priority: int, api_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RoutingRule": {
                "Type": "AWS::ApiGatewayV2::RoutingRule",
                "Properties": {
                    "DomainNameArn": domain_arn,
                    "Priority": priority,
                    "Conditions": [{"MatchBasePaths": {"AnyOf": ["widgets"]}}],
                    "Actions": [{"InvokeApi": {"ApiId": api_id, "Stage": "prod"}}],
                },
            },
        },
        "Outputs": {
            "RoutingRuleId": {"Value": {"Fn::GetAtt": ["RoutingRule", "RoutingRuleId"]}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ApiGatewayV2 RoutingRule at Priority 1,000,000 reaches CREATE_COMPLETE;
    one past that boundary fails the stack with the message "Priority must be between 1 and
    1,000,000."

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-routingrule.html
    """
    acm = ctx.client("acm")
    apigwv2 = ctx.client("apigatewayv2")
    ag = ctx.client("apigateway")
    cfn = ctx.client("cloudformation")

    domain = f"{ctx.unique_name('sim2real-xsvc-rrp-')}.example.com"
    domain_arn = f"arn:aws:apigateway:{ctx.region}::/domainnames/{domain}"

    cert_arn = _import_cert(acm, domain)
    _create_domain(ctx, apigwv2, domain, cert_arn)
    api_id = _build_rest_api(ctx, ag)

    # Positive control: the documented maximum, 1,000,000, is accepted.
    good_name = ctx.unique_name("sim2real-xsvc-rrp-ok-")
    good_id: dict[str, str] = {}
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_id["StackId"]) if good_id.get("StackId") else None)
    good_id["StackId"] = cfn.create_stack(
        StackName=good_name, TemplateBody=_template(domain_arn, 1000000, api_id),
        Tags=[{"Key": "sim2real", "Value": good_name}],
    )["StackId"]
    good_status = _wait_stack(cfn, good_id["StackId"])
    assert good_status == "CREATE_COMPLETE", (
        f"Priority=1000000, the documented maximum, must create cleanly; the stack ended "
        f"{good_status!r}: {[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in _stack_events(cfn, good_id['StackId']) if e['ResourceStatus'] == 'CREATE_FAILED']!r}"
    )
    good_rule_id = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=good_id["StackId"])["Stacks"][0]["Outputs"]
    }["RoutingRuleId"]
    rule = apigwv2.get_routing_rule(DomainName=domain, RoutingRuleId=good_rule_id)
    assert rule["Priority"] == 1000000, f"GetRoutingRule reports Priority={rule['Priority']!r}"

    # Break exactly one thing: 1,000,001 is past the documented 1..1,000,000 range.
    bad_name = ctx.unique_name("sim2real-xsvc-rrp-bad-")
    bad_id: dict[str, str] = {}
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_id["StackId"]) if bad_id.get("StackId") else None)
    bad_id["StackId"] = cfn.create_stack(
        StackName=bad_name, TemplateBody=_template(domain_arn, 1000001, api_id),
        Tags=[{"Key": "sim2real", "Value": bad_name}],
        OnFailure="DO_NOTHING",
    )["StackId"]
    bad_status = _wait_stack(cfn, bad_id["StackId"], {"CREATE_FAILED", "ROLLBACK_COMPLETE",
                                                       "ROLLBACK_FAILED", "CREATE_COMPLETE"})
    assert bad_status == "CREATE_FAILED", (
        f"Priority=1000001, one past the documented maximum, must fail the stack; it ended "
        f"{bad_status!r}"
    )
    failures = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in _stack_events(cfn, bad_id["StackId"])
        if e["LogicalResourceId"] == "RoutingRule" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(failures) == 1, f"expected exactly one CREATE_FAILED event for RoutingRule, got {failures!r}"
    message = _handler_message(failures[0][1] or "")
    assert message == "Priority must be between 1 and 1,000,000.", (
        f"RoutingRule's CREATE_FAILED reason carried API message {message!r}"
    )

    # The broken stack never produced a resource to list; the control's did, and still does.
    remaining = apigwv2.list_routing_rules(DomainName=domain).get("RoutingRules", [])
    assert [r["Priority"] for r in remaining] == [1000000], (
        f"ListRoutingRules on the domain reports {remaining!r}; only the control's rule should exist"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
