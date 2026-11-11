"""op-contract-deleteVpcEndpointServiceConfigurations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpcEndpointServiceConfigurations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpcEndpointServiceConfigurations deletes the real config, reports the bogus one in Unsuccessful."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.216.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "svc-vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.216.1.0/24", TagSpecifications=[_tag_spec(ctx, "subnet", "svc-subnet")]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    nlb_name = ctx.unique_name("sim2real-nlb-")[:32].rstrip("-")
    nlb = elbv2.create_load_balancer(
        Name=nlb_name, Subnets=[subnet_id], Type="network", Scheme="internal"
    )["LoadBalancers"][0]
    nlb_arn = nlb["LoadBalancerArn"]

    def _cleanup_nlb():
        _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn))
        _poll_until(
            lambda: _nlb_state(elbv2, nlb_arn),
            lambda s: s == "gone",
            timeout_s=180.0,
            interval_s=5.0,
            on_timeout="ignore",
        )

    ctx.on_cleanup(_cleanup_nlb)

    # the NLB must be fully provisioned ("active") before it can back a VPC endpoint service
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=180.0,
        interval_s=5.0,
    )

    created = ec2.create_vpc_endpoint_service_configuration(
        NetworkLoadBalancerArns=[nlb_arn],
        AcceptanceRequired=True,
        TagSpecifications=[_tag_spec(ctx, "vpc-endpoint-service", "svc")],
    )
    service_id = created["ServiceConfiguration"]["ServiceId"]
    state = {"deleted": False}

    def _cleanup_service():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id]))

    ctx.on_cleanup(_cleanup_service)

    described = _items(
        ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id]),
        "ServiceConfigurations",
        "ServiceConfigurationSet",
    )[0]
    assert described["ServiceId"] == service_id, f"expected ServiceId {service_id!r}, got {described['ServiceId']!r}"
    assert nlb_arn in described["NetworkLoadBalancerArns"], (
        f"expected {nlb_arn!r} among NetworkLoadBalancerArns, got {described['NetworkLoadBalancerArns']!r}"
    )

    # batch delete: one real service config id + one bogus one in the same request
    bogus_id = _mutate_id(service_id)
    delete_resp = ec2.delete_vpc_endpoint_service_configurations(ServiceIds=[service_id, bogus_id])
    state["deleted"] = True

    unsuccessful = delete_resp["Unsuccessful"]
    assert len(unsuccessful) == 1, f"expected exactly one Unsuccessful entry, got {unsuccessful!r}"
    assert unsuccessful[0]["ResourceId"] == bogus_id, (
        f"expected the Unsuccessful entry to name {bogus_id!r}, got {unsuccessful[0]['ResourceId']!r}"
    )
    assert unsuccessful[0]["Error"]["Code"] is not None and (
        unsuccessful[0]["Error"]["Code"].startswith("Invalid")
        and unsuccessful[0]["Error"]["Code"].endswith("NotFound")
    ), f"expected an Invalid*NotFound error for the bogus service config id, got {unsuccessful[0]['Error']}"

    # the real service configuration was still deleted despite the bogus one failing in the same batch
    gone_code = _error_code(
        lambda: ec2.describe_vpc_endpoint_service_configurations(ServiceIds=[service_id])
    )
    assert gone_code is not None and gone_code.startswith("Invalid") and gone_code.endswith("NotFound"), (
        f"expected an Invalid*NotFound error describing a deleted service configuration, got {gone_code!r}"
    )

    # the dead id is not just unreadable — it also rejects a mutation, not just a read
    modify_code = _error_code(
        lambda: ec2.modify_vpc_endpoint_service_configuration(ServiceId=service_id, AcceptanceRequired=False)
    )
    assert modify_code is not None and modify_code.startswith("Invalid") and modify_code.endswith("NotFound"), (
        f"expected an Invalid*NotFound error modifying a deleted service configuration, got {modify_code!r}"
    )

# ===== helpers =====
def _items(resp: dict, *keys: str) -> list:
    for key in keys:
        if key in resp:
            return resp[key]
    return []


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("expected the call on a deleted service configuration to be refused, it succeeded")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _nlb_state(elbv2, arn):
    try:
        elbv2.describe_load_balancers(LoadBalancerArns=[arn])
        return "present"
    except Exception as exc:  # noqa: BLE001 - broad by design for cleanup polling
        if "LoadBalancerNotFound" in type(exc).__name__ or "LoadBalancerNotFound" in str(exc):
            return "gone"
        return "present"


def _mutate_id(real_id: str) -> str:
    return real_id[:-1] + ("0" if real_id[-1] != "0" else "1")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, on_timeout="raise"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if on_timeout == "ignore":
        return last
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


# AWS-managed ENIs (endpoints, load balancers, instances) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
