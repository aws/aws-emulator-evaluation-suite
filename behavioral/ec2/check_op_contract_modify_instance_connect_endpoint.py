"""op-contract-modify-instance-connect-endpoint."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-instance-connect-endpoint"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceConnectEndpoint swaps the endpoint's security groups and rejects an unknown endpoint ID."""
    ec2 = ctx.client("ec2")

    vpc_id, subnet_id = _new_vpc_and_subnet(ec2, ctx)

    sg1 = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg1-"),
        Description="sim2real behavioral test sg1",
        VpcId=vpc_id,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg(ec2, sg1))
    sg2 = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg2-"),
        Description="sim2real behavioral test sg2",
        VpcId=vpc_id,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg(ec2, sg2))

    endpoint_name = ctx.unique_name("sim2real-behav-eice-")
    endpoint_id = _create_endpoint_with_retry(
        ec2, subnet_id, sg1, endpoint_name
    )["InstanceConnectEndpointId"]
    ctx.on_cleanup(
        lambda: ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=endpoint_id)
    )

    endpoint = _poll_until(
        lambda: ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ][0],
        lambda e: e["State"] in ("create-complete", "create-failed"),
        timeout_s=420,
        interval_s=10,
    )
    assert endpoint["State"] == "create-complete", endpoint

    ec2.modify_instance_connect_endpoint(
        InstanceConnectEndpointId=endpoint_id, SecurityGroupIds=[sg2]
    )
    described = _poll_until(
        lambda: ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ][0],
        lambda e: e["State"] in ("update-complete", "update-failed"),
        timeout_s=120,
        interval_s=5,
    )
    assert described["State"] == "update-complete", described
    assert described["SecurityGroupIds"] == [sg2], described

    code, msg = _error(
        lambda: ec2.modify_instance_connect_endpoint(
            InstanceConnectEndpointId="eice-00000000000000000", SecurityGroupIds=[sg2]
        )
    )
    assert code == "InvalidInstanceConnectEndpointId.NotFound", (
        f"expected InvalidInstanceConnectEndpointId.NotFound, got {code}"
    )
    expected = "The instance-connect-endpoint ID 'eice-00000000000000000' does not exist"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


# ===== helpers =====
def _new_vpc_and_subnet(ec2, ctx):
    """A dedicated VPC/subnet rather than the ambient default one: a freshly provisioned account
    may not have a default VPC, and a shared default subnet's own low per-subnet Instance Connect
    Endpoint quota is contended by every other check that reaches for it.
    """
    vpc_id = ec2.create_vpc(
        CidrBlock="10.98.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.98.1.0/24",
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet(ec2, subnet_id))
    return vpc_id, subnet_id


def _delete_vpc(ec2, vpc_id: str) -> None:
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


def _delete_subnet(ec2, subnet_id: str) -> None:
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


def _create_endpoint_with_retry(ec2, subnet_id, sg_id, name, *, timeout_s=180.0, interval_s=15.0):
    """CreateInstanceConnectEndpoint against a low per-account/region endpoint limit.

    A prior interrupted run of this same check (or another concurrent run) can leak an
    Instance Connect Endpoint that still counts against the account's regional quota.
    Self-heal by deleting any leaked endpoints tagged from earlier runs of this check,
    then poll-retry: deleting an endpoint does not free its quota slot instantaneously.

    If the quota is still exhausted after self-healing every leaked endpoint from this
    check and waiting out the full bound, the account/region's Instance Connect Endpoint
    quota is genuinely consumed by endpoints outside this check's control -- an
    environment capacity constraint this check cannot resolve, so it fails loudly.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    cleaned_up = False
    last_error = None
    while True:
        try:
            return ec2.create_instance_connect_endpoint(
                SubnetId=subnet_id,
                SecurityGroupIds=[sg_id],
                TagSpecifications=[
                    {
                        "ResourceType": "instance-connect-endpoint",
                        "Tags": [{"Key": "Name", "Value": name}],
                    }
                ],
            )["InstanceConnectEndpoint"]
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            last_error = e

        if not cleaned_up:
            leaked = ec2.describe_instance_connect_endpoints(
                Filters=[
                    {"Name": "tag-key", "Values": ["Name"]},
                    {
                        "Name": "state",
                        "Values": ["create-in-progress", "create-complete", "create-failed"],
                    },
                ]
            )["InstanceConnectEndpoints"]
            leaked_ids = [
                e["InstanceConnectEndpointId"]
                for e in leaked
                for t in e.get("Tags", [])
                if t.get("Key") == "Name"
                and str(t.get("Value", "")).startswith("sim2real-behav-eice-")
            ]
            for leaked_id in leaked_ids:
                try:
                    ec2.delete_instance_connect_endpoint(InstanceConnectEndpointId=leaked_id)
                except ClientError:
                    pass
            cleaned_up = True

        if time.monotonic() >= deadline:
            raise AssertionError(
                "account/region's Instance Connect Endpoint quota is exhausted by "
                f"endpoints outside this check's control even after self-healing leaked "
                f"endpoints: {last_error}"
            )
        time.sleep(interval_s)


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_sg(ec2, group_id: str) -> None:
    try:
        _delete_net(ec2, "delete_security_group", GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


# EC2 network deletes wait for AWS-managed ENIs to leave: a resource in this VPC deletes asynchronously,
# so DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation until its ENIs go. Retry
# that code to one deadline shared by the check's network deletes, then raise naming the ENIs left.
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
