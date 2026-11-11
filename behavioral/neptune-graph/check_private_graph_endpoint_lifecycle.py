"""private-graph-endpoint-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "private-graph-endpoint-lifecycle"
GROUP = "cross-service"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePrivateGraphEndpoint yields an AVAILABLE endpoint in the requested VPC and subnet; after
    DeletePrivateGraphEndpoint, a read and a second delete fail with ResourceNotFoundException and the
    exact message."""
    ec2 = ctx.client("ec2")
    ng = ctx.client("neptune-graph")

    net_name = ctx.unique_name("sim2real-ngep-")
    net_tags = [{"Key": "Name", "Value": net_name}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/24", TagSpecifications=[{"ResourceType": "vpc", "Tags": net_tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.93.0.0/25",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": net_tags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    graph_id = _create_available_graph(ctx, ng)

    ng.create_private_graph_endpoint(graphIdentifier=graph_id, vpcId=vpc_id, subnetIds=[subnet_id])

    def _try_delete_ep() -> bool:
        try:
            ng.delete_private_graph_endpoint(graphIdentifier=graph_id, vpcId=vpc_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ConflictException":
                return False
            if code != "ResourceNotFoundException":
                raise
        return True

    def _cleanup_ep() -> None:
        # DeletePrivateGraphEndpoint answers ConflictException while the endpoint is still being created.
        _poll_until(_try_delete_ep, bool, timeout_s=300, interval_s=2)

    ctx.on_cleanup(_cleanup_ep)

    status = _poll_until(
        lambda: ng.get_private_graph_endpoint(graphIdentifier=graph_id, vpcId=vpc_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert status == "AVAILABLE", f"expected private graph endpoint AVAILABLE, got {status!r}"

    got = ng.get_private_graph_endpoint(graphIdentifier=graph_id, vpcId=vpc_id)
    assert got["vpcId"] == vpc_id, f"expected vpcId {vpc_id!r}, got {got['vpcId']!r}"
    assert subnet_id in got["subnetIds"], f"expected {subnet_id!r} in subnetIds, got {got['subnetIds']!r}"

    ng.delete_private_graph_endpoint(graphIdentifier=graph_id, vpcId=vpc_id)
    expected_gone = f"Private Graph Endpoint to Graph: {graph_id} from VPC: {vpc_id} does not exist"
    gone_code, gone_msg = _poll_until(
        lambda: _error(lambda: ng.get_private_graph_endpoint(graphIdentifier=graph_id, vpcId=vpc_id), poll=True),
        lambda r: r[0] == "ResourceNotFoundException",
        timeout_s=300,
        interval_s=10,
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted endpoint, got {gone_code!r}"
    )
    assert gone_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_msg!r}"

    redelete_code, redelete_msg = _error(
        lambda: ng.delete_private_graph_endpoint(graphIdentifier=graph_id, vpcId=vpc_id)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-deleting the already-gone endpoint to fail with ResourceNotFoundException, "
        f"got {redelete_code!r}"
    )
    assert redelete_msg == expected_gone, f"expected message {expected_gone!r}, got {redelete_msg!r}"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _error(fn, *, poll=False):
    """Return the (code, message) of the ClientError fn() raises. A success raises AssertionError;
    with poll=True it returns a sentinel no error code can equal, so a poll keeps waiting."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    if poll:
        return "<call succeeded>", None
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _create_available_graph(ctx, ng, *, provisioned_memory=16, deletion_protection=False, replica_count=0, name=None):
    graph_name = name or ctx.unique_name("sim2real-ng-")
    resp = ng.create_graph(
        graphName=graph_name,
        provisionedMemory=provisioned_memory,
        deletionProtection=deletion_protection,
        replicaCount=replica_count,
        publicConnectivity=False,
    )
    graph_id = resp["id"]

    def _cleanup() -> None:
        def _settle(timeout_s):
            return _poll_until(
                lambda: ng.get_graph(graphIdentifier=graph_id),
                lambda g: g["status"] not in ("CREATING", "UPDATING", "DELETING", "RESETTING", "STARTING", "STOPPING", "SNAPSHOTTING", "IMPORTING"),
                timeout_s=timeout_s,
                interval_s=2,
            )

        try:
            if _settle(600).get("deletionProtection"):
                ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
                _settle(120)
            ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=1500,
        interval_s=15,
    )
    if status != "AVAILABLE":
        raise AssertionError(f"graph {graph_id} did not reach AVAILABLE (status={status})")
    return graph_id


# Asynchronous deletes in this VPC leave ENIs behind for a while, so DeleteSubnet / DeleteVpc fail with
# DependencyViolation: wait (bounded) for the ENIs to go, retry DependencyViolation in the same window
# (shared by all of one check's network deletes), then raise naming the ENIs still attached.
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
