"""put-managed-insight-rules-invalid-template-name-rejected-per-item."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-managed-insight-rules-invalid-template-name-rejected-per-item"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
#: Violates the Smithy TemplateName @pattern (must start and end with an alphanumeric).
_MALFORMED = "-bad-template-"
#: Matches the pattern, names no template.
_UNKNOWN = "NoSuchTemplate-v1"
_NOT_FOUND = {
    "ExceptionType": "ResourceNotFoundException",
    "FailureCode": "TEMPLATE_NAME",
    "FailureDescription": "Could not find template with the specified templateName.",
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedInsightRules refuses an invalid TemplateName per item and still applies the valid item.

    Pattern-breaking and unknown names both fail as not-found; only the valid template is enabled,
    as a managed rule bound to the resource, and no rule exists for either bad name.
    """
    cw = ctx.client("cloudwatch")
    # CloudWatch offers managed templates per resource type; a VPC endpoint service has them.
    resource_arn = _provision_vpc_endpoint_service(ctx)

    offered = cw.list_managed_insight_rules(ResourceARN=resource_arn)["ManagedRules"]
    assert offered, f"ListManagedInsightRules offered no template for {resource_arn!r}"
    assert not [r for r in offered if r.get("RuleState")], (
        f"a fresh resource must have no managed rule enabled yet, got {offered!r}"
    )
    template = offered[0]["TemplateName"]

    resp = cw.put_managed_insight_rules(
        ManagedRules=[
            {"TemplateName": template, "ResourceARN": resource_arn, "Tags": _TAGS},
            {"TemplateName": _MALFORMED, "ResourceARN": resource_arn},
            {"TemplateName": _UNKNOWN, "ResourceARN": resource_arn},
        ]
    )
    ctx.on_cleanup(lambda: _delete_enabled_rules(cw, resource_arn))
    failures = sorted(resp["Failures"], key=lambda f: f["FailureResource"])
    want = [
        {"FailureResource": _MALFORMED, **_NOT_FOUND},
        {"FailureResource": _UNKNOWN, **_NOT_FOUND},
    ]
    assert failures == want, f"expected exactly the two not-found item failures {want!r}, got {failures!r}"

    listed = cw.list_managed_insight_rules(ResourceARN=resource_arn)["ManagedRules"]
    enabled = {r["TemplateName"]: r["RuleState"] for r in listed if r.get("RuleState")}
    assert list(enabled) == [template], (
        f"exactly the valid template {template!r} must be enabled, got {enabled!r}"
    )
    assert enabled[template]["State"] == "ENABLED", f"rule state {enabled[template]!r}"
    names = {r["TemplateName"] for r in listed}
    assert not names & {_MALFORMED, _UNKNOWN}, f"a refused template name is listed: {sorted(names)!r}"

    rule_name = enabled[template]["RuleName"]
    rules = {r["Name"]: r for r in _describe_insight_rules(cw)}
    assert rule_name in rules, f"DescribeInsightRules has no rule {rule_name!r}"
    rule = rules[rule_name]
    assert rule["ManagedRule"] is True, f"{rule_name!r} must be a managed rule, got {rule!r}"
    assert rule["State"] == "ENABLED", f"{rule_name!r} state {rule['State']!r}"
    resource = json.loads(rule["Definition"])["Resource"]
    assert resource == resource_arn, f"the managed rule is bound to {resource!r}, not {resource_arn!r}"
    stray = [n for n, r in rules.items() if _MALFORMED in n or _UNKNOWN in n]
    assert stray == [], f"a refused template produced insight rules {stray!r}"


def _describe_insight_rules(cw) -> list[dict]:
    rules, token = [], None
    while True:
        page = cw.describe_insight_rules(**({"NextToken": token} if token else {}))
        rules.extend(page["InsightRules"])
        token = page.get("NextToken")
        if not token:
            return rules


def _delete_enabled_rules(cw, resource_arn) -> None:
    listed = cw.list_managed_insight_rules(ResourceARN=resource_arn)["ManagedRules"]
    names = [r["RuleState"]["RuleName"] for r in listed if r.get("RuleState")]
    if names:
        resp = cw.delete_insight_rules(RuleNames=names)
        assert resp["Failures"] == [], f"DeleteInsightRules failed: {resp['Failures']!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _provision_vpc_endpoint_service(ctx) -> str:
    """Create a VPC, a subnet, an internal NLB and an endpoint service on it; return its ARN."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    name_tag = ctx.unique_name("sim2real-behav-mirpi-")
    tag = [{"Key": "Name", "Value": name_tag}, *_TAGS]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.193.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert zones, "no available AZ in this region"
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.193.1.0/24",
        AvailabilityZone=zones[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    nlb_arn = elbv2.create_load_balancer(
        Name=name_tag[:32].rstrip("-"),
        Subnets=[subnet_id],
        Scheme="internal",
        Type="network",
        Tags=tag,
    )["LoadBalancers"][0]["LoadBalancerArn"]

    def _delete_nlb_and_wait() -> None:
        elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn)
        elbv2.get_waiter("load_balancers_deleted").wait(
            LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_delete_nlb_and_wait)
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])["LoadBalancers"][0][
            "State"
        ]["Code"],
        lambda code: code == "active",
        timeout_s=300.0,
        interval_s=10.0,
    )

    service_id = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=False,
        TagSpecifications=[{"ResourceType": "vpc-endpoint-service", "Tags": tag}],
    )["ServiceConfiguration"]["ServiceId"]
    ctx.on_cleanup(
        lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id])
    )
    _poll_until(
        lambda: ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id])[
            "ServiceConfigurations"
        ][0]["ServiceState"],
        lambda state: state == "Available",
        timeout_s=120.0,
        interval_s=5.0,
    )
    # The endpoint service ARN lives in the NLB's partition, region and account.
    _, partition, _, region, account, _ = nlb_arn.split(":", 5)
    return f"arn:{partition}:ec2:{region}:{account}:vpc-endpoint-service/{service_id}"


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer in
# this VPC deletes ASYNCHRONOUSLY: its delete returns while its ENIs still sit in the subnet, so an
# immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final
# failure naming the ENIs. Teardown-only: nothing run() executes calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
