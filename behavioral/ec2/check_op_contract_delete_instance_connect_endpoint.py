"""op-contract-delete-instance-connect-endpoint."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-instance-connect-endpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteInstanceConnectEndpoint: a real endpoint reaches create-complete, deletes cleanly,
    and moves towards delete-complete; deleting an unknown endpoint ID is rejected with the
    documented NotFound error.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-eice-")

    vpc = ec2.create_vpc(
        CidrBlock="10.72.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az = azs[0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.72.0.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    endpoint = ec2.create_instance_connect_endpoint(
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance-connect-endpoint", "Tags": [{"Key": "Name", "Value": name}]}],
    )["InstanceConnectEndpoint"]
    endpoint_id = endpoint["InstanceConnectEndpointId"]
    ctx.on_cleanup(
        lambda: _ignore(lambda: ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=endpoint_id))
    )

    def create_probe():
        eps = ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ]
        return eps[0]["State"] if eps else "gone"

    # Real EC2 Instance Connect Endpoint provisioning can take well over five minutes to reach
    # a terminal state, so use a generous bound here rather than the tight window that flakes
    # against real AWS.
    state = _poll_until(create_probe, lambda s: s in ("create-complete", "create-failed"), timeout_s=900, interval_s=15)
    assert state == "create-complete", f"endpoint failed to become available: {state!r}"

    resp = ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=endpoint_id)
    resp_endpoint = resp["InstanceConnectEndpoint"]
    assert resp_endpoint["InstanceConnectEndpointId"] == endpoint_id, (
        f"expected delete response to echo {endpoint_id!r}, got {resp_endpoint['InstanceConnectEndpointId']!r}"
    )
    assert resp_endpoint["State"] in ("delete-in-progress", "delete-complete"), (
        f"expected delete response state in ('delete-in-progress', 'delete-complete'), got {resp_endpoint['State']!r}"
    )

    def delete_probe():
        eps = ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ]
        return eps[0]["State"] if eps else "gone"

    final_state = _poll_until(delete_probe, lambda s: s in ("delete-complete", "gone"), timeout_s=180, interval_s=5)
    assert final_state in ("delete-complete", "gone"), final_state

    # The endpoint this check deleted is also unusable: a second delete on the identical,
    # now-dead id fails, distinct from the mutation succeeding a second time.
    redelete_code, redelete_message = _error_of(
        lambda: ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=endpoint_id)
    )
    assert redelete_code == "InvalidInstanceConnectEndpointId.NotFound", (
        f"expected re-delete of the dead endpoint id to fail with InvalidInstanceConnectEndpointId.NotFound, "
        f"got {redelete_code!r}"
    )
    assert redelete_message == _ice_not_found(endpoint_id), redelete_message

    # Error boundary: deleting an unknown (never-created) EC2 Instance Connect Endpoint ID is
    # rejected the same way as the now-dead one above.
    fake_id = _zeroed_id(endpoint_id)
    code, message = _error_of(lambda: ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=fake_id))
    assert code == "InvalidInstanceConnectEndpointId.NotFound", f"unexpected error code {code!r}"
    assert message == _ice_not_found(fake_id), message


# ===== helpers =====
def _ice_not_found(endpoint_id: str) -> str:
    return (
        f"The Instance Connect Endpoint {endpoint_id} does not exist. Add an existing Instance "
        "Connect Endpoint ID and retry your request."
    )


def _error_of(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceConnectEndpointId.NotFound":
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied, last value={last!r}")


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
