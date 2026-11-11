"""deploy-domain-name-association-cfn-behavioral."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-domain-name-association-cfn-behavioral"
GROUP = "deploy"
SERVICES = ["appsync"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  DomainNameParam:
    Type: String
  CertificateArnParam:
    Type: String
  ApiIdParam:
    Type: String
Resources:
  BehavDomainName:
    Type: AWS::AppSync::DomainName
    Properties:
      DomainName: !Ref DomainNameParam
      CertificateArn: !Ref CertificateArnParam
  BehavDomainAssociation:
    Type: AWS::AppSync::DomainNameApiAssociation
    DependsOn: BehavDomainName
    Properties:
      ApiId: !Ref ApiIdParam
      DomainName: !Ref DomainNameParam
Outputs:
  DomainNameOut:
    Value: !Ref DomainNameParam
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control", "requires:dns-baseline")
def run(ctx) -> None:
    """A DomainName + DomainNameApiAssociation deployed via CloudFormation reaches a real SUCCESS
    association via GetApiAssociation, and stack deletion removes it from ListDomainNames. AppSync
    accepts only a certificate ACM itself issued, so the domain lives under the DNS baseline zone."""
    appsync = ctx.client("appsync")
    api_name = ctx.unique_name("sim2real-domapi-")
    graphql_api = appsync.create_graphql_api(
        name=api_name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = graphql_api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    # AppSync's CreateDomainName accepts only a certificate ACM itself issued, so the domain
    # lives under a zone that can DNS-validate one.
    zone_id, apex = _dns_zone(ctx)
    domain_name = f"{_domain_label()}.{apex}"
    cert_arn = _dns_validated_cert(ctx, zone_id, domain_name)

    stack_name = ctx.unique_name("sim2real-domstack-")
    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        stack_name,
        {
            "DomainNameParam": domain_name,
            "CertificateArnParam": cert_arn,
            "ApiIdParam": api_id,
        },
    )
    assert outputs["DomainNameOut"] == domain_name, (
        f"expected the stack output to echo the domain name {domain_name!r}, got {outputs.get('DomainNameOut')!r}"
    )

    association = _poll_until(
        lambda: appsync.get_api_association(domainName=domain_name)["apiAssociation"],
        lambda a: a["associationStatus"] in ("SUCCESS", "FAILED"),
        timeout_s=1800,
        interval_s=20,
    )
    assert association["associationStatus"] == "SUCCESS", (
        f"expected the CFN-deployed association to reach SUCCESS, got {association!r}"
    )
    assert association["apiId"] == api_id, (
        f"expected the association to point at {api_id!r}, got {association['apiId']!r}"
    )

    domain_cfg = appsync.get_domain_name(domainName=domain_name)["domainNameConfig"]
    assert domain_cfg["domainName"] == domain_name, (
        f"expected an independent GetDomainName read to echo {domain_name!r}, got {domain_cfg.get('domainName')!r}"
    )

    names_before = [d["domainName"] for d in appsync.list_domain_names().get("domainNameConfigs", [])]
    assert domain_name in names_before, (
        f"expected {domain_name!r} in ListDomainNames while the stack exists, got {names_before!r}"
    )

    _delete_stack_and_wait(ctx, stack_name)

    names_after = [d["domainName"] for d in appsync.list_domain_names().get("domainNameConfigs", [])]
    assert domain_name not in names_after, (
        f"expected {domain_name!r} gone from ListDomainNames after stack deletion, still present in {names_after!r}"
    )

    code, message = _error_code(lambda: appsync.get_domain_name(domainName=domain_name))
    assert code == "NotFoundException", (
        f"expected GetDomainName for the deleted domain to raise NotFoundException, got {code!r}"
    )
    assert message == "Domain name not found", (
        f"expected the exact NotFoundException message AWS returns, got {message!r}"
    )
    assoc_code, assoc_message = _error_code(lambda: appsync.get_api_association(domainName=domain_name))
    assert assoc_code == "NotFoundException", (
        f"expected GetApiAssociation for the deleted domain to raise NotFoundException, got {assoc_code!r}"
    )
    assert assoc_message == "Domain name not found", (
        f"expected the exact NotFoundException message AWS returns, got {assoc_message!r}"
    )


# ===== helpers =====


def _deploy_cfn(ctx, template_body: str, stack_name: str, parameters: dict) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    except WaiterError as exc:
        reasons = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '?')}"
            for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            if e["ResourceStatus"].endswith("FAILED")
        ]
        raise AssertionError(
            f"stack {stack_name} failed to create with parameters {parameters}: {reasons}"
        ) from exc
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected the stack to reach CREATE_COMPLETE, got {stack['StackStatus']}"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 413})


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, so a
    target that never actually deleted the resource cannot pass by returning a falsy code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}


def _dns_zone(ctx):
    """(zone id, apex) of the DNS baseline zone the check writes validation records into
    (``requires:dns-baseline``, docs/TAXONOMY.md)."""
    route53 = ctx.client("route53")
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            if zone["Config"].get("PrivateZone"):
                continue
            zone_id = zone["Id"].rsplit("/", 1)[-1]
            tags = route53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=zone_id)
            if _BASELINE_TAG in tags["ResourceTagSet"]["Tags"]:
                return zone_id, zone["Name"].rstrip(".")
    raise AssertionError(
        "this account has no DNS baseline zone (a public hosted zone carrying the DNS "
        "baseline tag, delegated from its parent); provision one before running this check"
    )


def _domain_label() -> str:
    """A label short enough that label.apex fits ACM's 64-octet first domain name."""
    return f"sim2real{uuid.uuid4().hex[:8]}"


def _dns_validated_cert(ctx, zone_id: str, domain: str) -> str:
    """An ACM certificate for ``domain`` in us-east-1, issued by DNS validation through
    ``zone_id``: AppSync's CreateDomainName accepts only a certificate ACM itself issued, from
    us-east-1 (custom domains are CloudFront-backed)."""
    acm = ctx.client("acm", region="us-east-1")
    route53 = ctx.client("route53")
    arn = acm.request_certificate(
        DomainName=domain,
        ValidationMethod="DNS",
        IdempotencyToken=uuid.uuid4().hex[:24],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, arn))

    def _record():
        options = acm.describe_certificate(CertificateArn=arn)["Certificate"].get(
            "DomainValidationOptions", []
        )
        return options[0].get("ResourceRecord") if options else None

    record = _wait_for(_record, lambda r: r is not None, 120, f"validation record of {domain}")
    record_set = {
        "Name": record["Name"],
        "Type": record["Type"],
        "TTL": 60,
        "ResourceRecords": [{"Value": record["Value"]}],
    }
    route53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Changes": [{"Action": "UPSERT", "ResourceRecordSet": record_set}]},
    )
    ctx.on_cleanup(
        lambda: route53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": record_set}]},
        )
    )
    _wait_for(
        lambda: acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"],
        lambda s: s in ("ISSUED", "FAILED", "VALIDATION_TIMED_OUT"),
        600,
        f"certificate for {domain} to leave PENDING_VALIDATION",
    )
    status = acm.describe_certificate(CertificateArn=arn)["Certificate"]["Status"]
    assert status == "ISSUED", f"DNS-validated certificate for {domain} ended {status!r}"
    return arn


def _wait_for(probe, predicate, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(5)
    raise AssertionError(f"{what} not met within {timeout_s}s (last={last!r})")


def _delete_certificate(acm, arn: str, timeout_s: float = 180.0) -> None:
    """AppSync releases a deleted domain's certificate a little after DeleteDomainName returns."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
