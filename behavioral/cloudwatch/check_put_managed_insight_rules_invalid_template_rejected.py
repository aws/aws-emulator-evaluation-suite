"""put-managed-insight-rules-invalid-template-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-managed-insight-rules-invalid-template-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedInsightRules reports an unknown TemplateName in Failures, not as a top-level error.

    The failure names the template and enables nothing; a real template on the same resource
    succeeds first as the positive control.
    """
    cw = ctx.client("cloudwatch")
    prereqs = _provision_vpc_endpoint_service(ctx)
    resource_arn = prereqs["resource_arn"]

    available = cw.list_managed_insight_rules(ResourceARN=resource_arn).get("ManagedRules", [])
    if not available:
        raise AssertionError(
            "no managed Contributor Insights rule templates are available for a VPC "
            "PrivateLink endpoint service in this account/region, so the positive control "
            "cannot be established"
        )
    real_template = available[0]["TemplateName"]

    positive = cw.put_managed_insight_rules(
        ManagedRules=[{"TemplateName": real_template, "ResourceARN": resource_arn}]
    )
    assert positive.get("Failures", []) == [], (
        f"positive control failed: a real, discovered TemplateName was rejected: {positive}"
    )

    def _cleanup_enabled_rule() -> None:
        rules = cw.list_managed_insight_rules(ResourceARN=resource_arn)["ManagedRules"]
        rule_names = [r["RuleState"]["RuleName"] for r in rules if r.get("RuleState")]
        if rule_names:
            cw.delete_insight_rules(RuleNames=rule_names)

    ctx.on_cleanup(_cleanup_enabled_rule)

    enabled = cw.list_managed_insight_rules(ResourceARN=resource_arn)["ManagedRules"]
    assert any(
        r.get("TemplateName") == real_template and r.get("RuleState") is not None
        for r in enabled
    ), f"positive control did not enable a rule visible via ListManagedInsightRules: {enabled}"

    bogus_template = "AWS/NoSuchService/NotARealTemplate"

    response = cw.put_managed_insight_rules(
        ManagedRules=[{"TemplateName": bogus_template, "ResourceARN": resource_arn}]
    )

    failures = response.get("Failures", [])
    assert len(failures) == 1, (
        f"expected exactly one partial failure for the invalid template, got {response}"
    )
    failure = failures[0]
    # The service identifies the failed item by the offending TemplateName (not the
    # ResourceARN) in the FailureResource field -- the rejection is about the unknown
    # template, and the ARN itself was syntactically fine.
    assert bogus_template in failure.get("FailureResource", ""), failure
    # The failure should carry concrete error details (exception type, failure code, and a
    # human-readable description) identifying the problem. The exact exception/code string
    # AWS uses for an unrecognized template is not part of the documented contract, so rather
    # than pin to a specific value, assert that all three fields are populated and that the
    # description actually calls out the offending template.
    assert failure.get("ExceptionType"), failure
    assert failure.get("FailureCode"), failure
    description = failure.get("FailureDescription", "")
    assert description, failure
    combined = (
        f"{failure.get('ExceptionType', '')} {failure.get('FailureCode', '')} {description}"
    ).lower()
    assert "template" in combined, (
        f"expected the failure to reference the invalid template name, got {failure}"
    )

    # The forbidden effect did not happen: the bogus template never appears as an entry, and
    # the set of *enabled* rules for this resource is unchanged from right after the positive
    # control -- the rejected call enabled nothing on top of it.
    listed = cw.list_managed_insight_rules(ResourceARN=resource_arn)["ManagedRules"]
    assert not any(r.get("TemplateName") == bogus_template for r in listed), listed
    enabled_after = {
        r["TemplateName"] for r in listed if r.get("RuleState") is not None
    }
    enabled_before = {
        r["TemplateName"] for r in enabled if r.get("RuleState") is not None
    }
    assert enabled_after == enabled_before, (
        f"expected no change in enabled rules after the rejected call, "
        f"before={enabled_before} after={enabled_after}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _provision_vpc_endpoint_service(ctx: Any) -> dict[str, str]:
    """Create the minimum viable VPC PrivateLink endpoint service (VPC + subnet + internal NLB)."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    name_tag = ctx.unique_name("sim2real-behav-pmirtr-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.192.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name_tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.192.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name_tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    nlb = elbv2.create_load_balancer(
        Name=name_tag[:32].rstrip("-"),
        Subnets=[subnet_id],
        Scheme="internal",
        Type="network",
        Tags=[{"Key": "Name", "Value": name_tag}],
    )["LoadBalancers"][0]
    nlb_arn = nlb["LoadBalancerArn"]

    def _delete_nlb_and_wait() -> None:
        elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn)
        elbv2.get_waiter("load_balancers_deleted").wait(
            LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_delete_nlb_and_wait)

    active = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=240.0,
        interval_s=10.0,
    )
    if active != "active":
        raise AssertionError("network load balancer never reached the active state")

    svc = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=False,
        TagSpecifications=[
            {"ResourceType": "vpc-endpoint-service", "Tags": [{"Key": "Name", "Value": name_tag}]}
        ],
    )["ServiceConfiguration"]
    service_id = svc["ServiceId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))

    _poll_until(
        lambda: ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id])[
            "ServiceConfigurations"
        ][0]["ServiceState"],
        lambda state: state == "Available",
        timeout_s=120.0,
        interval_s=5.0,
    )

    resource_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:vpc-endpoint-service/{service_id}"
    return {"resource_arn": resource_arn, "service_id": service_id, "nlb_arn": nlb_arn}


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer in
# this VPC deletes ASYNCHRONOUSLY: its delete returns while its ENIs still sit in the subnet, so an
# immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final
# failure naming the ENIs. Teardown-only: nothing run() executes calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
