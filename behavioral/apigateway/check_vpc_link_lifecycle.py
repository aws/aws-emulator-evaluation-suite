"""vpc-link-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vpc-link-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink -> AVAILABLE status -> GetVpcLink -> UpdateVpcLink -> DeleteVpcLink -> 404 on get."""
    apigw = ctx.client("apigateway")
    nlb_arn = _create_internal_nlb(ctx)

    name = ctx.unique_name("sim2real-apigw-vpclink-")
    created = apigw.create_vpc_link(name=name, targetArns=[nlb_arn], description="sim2real vpc link")
    vpc_link_id = created["id"]

    def _cleanup_vpc_link():
        try:
            state = apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        if state in ("PENDING", "AVAILABLE"):
            _poll_until(
                lambda: _safe_status(apigw, vpc_link_id),
                lambda s: s in ("AVAILABLE", "FAILED", None),
                timeout_s=300, interval_s=10,
            )
        try:
            apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_vpc_link)
    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"
    assert created["targetArns"] == [nlb_arn], (
        f"expected created targetArns {[nlb_arn]!r}, got {created['targetArns']!r}"
    )

    # A VPC link's own PENDING -> AVAILABLE transition is the dominant cost of this check.
    status = _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=900, interval_s=10,
    )
    if status != "AVAILABLE":
        raise AssertionError(
            f"VPC link never reached AVAILABLE (status={status}, "
            f"statusMessage={apigw.get_vpc_link(vpcLinkId=vpc_link_id).get('statusMessage')!r})",
        )

    got = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert got["name"] == name, f"expected GetVpcLink name {name!r}, got {got['name']!r}"
    assert got["targetArns"] == [nlb_arn], (
        f"expected GetVpcLink targetArns {[nlb_arn]!r}, got {got['targetArns']!r}"
    )

    new_name = name + "-renamed"
    apigw.update_vpc_link(
        vpcLinkId=vpc_link_id,
        patchOperations=[{"op": "replace", "path": "/name", "value": new_name}],
    )
    status = _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=30, interval_s=5,
    )
    updated = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert updated["name"] == new_name, updated

    apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
    _poll_until(
        lambda: _safe_status(apigw, vpc_link_id),
        lambda s: s is None,
        timeout_s=120, interval_s=5,
    )
    not_found = ("NotFoundException", "Invalid Vpc Link identifier specified")
    err = _client_error(lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id))
    assert (err.get("Code"), err.get("Message")) == not_found, (
        f"expected GetVpcLink on the deleted id to fail with {not_found!r}, got {err!r}"
    )

    err = _client_error(
        lambda: apigw.update_vpc_link(
            vpcLinkId=vpc_link_id,
            patchOperations=[{"op": "replace", "path": "/name", "value": name + "-after-delete"}],
        )
    )
    assert (err.get("Code"), err.get("Message")) == not_found, (
        f"expected UpdateVpcLink on the deleted id to fail with {not_found!r}, got {err!r}"
    )


# ===== helpers (self-contained) =====

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_status(apigw, vpc_link_id: str):
    try:
        return apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"]
    except Exception:
        return None


def _create_internal_nlb(ctx) -> str:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    tag = ctx.unique_name("sim2real-apigw-nlb-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.223.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.223.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    lb_name = tag[:32].rstrip("-")
    lb = elbv2.create_load_balancer(
        Name=lb_name, Type="network", Scheme="internal", Subnets=[subnet_id],
        Tags=[{"Key": "Name", "Value": tag}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]

    def _cleanup_nlb():
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
        _poll_until(
            lambda: _nlb_exists(elbv2, lb_arn),
            lambda exists: not exists,
            timeout_s=180, interval_s=10,
        )

    ctx.on_cleanup(_cleanup_nlb)

    # A VPC link to a load balancer that is still provisioning goes FAILED ("NLB is not in
    # active state"), so wait for the NLB's terminal state before CreateVpcLink.
    state = _poll_until(
        lambda: _nlb_state(elbv2, lb_arn),
        lambda s: s in ("active", "failed"),
        timeout_s=600, interval_s=10,
    )
    if state != "active":
        raise AssertionError(f"internal NLB never reached active (state={state!r})")
    return lb_arn


def _nlb_state(elbv2, lb_arn: str):
    return elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"]


def _nlb_exists(elbv2, lb_arn: str) -> bool:
    try:
        elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        return False


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached. Every other error propagates. Teardown-only: nothing run()
# executes calls this, so it cannot change the verdict. The window is shared by all of one check's
# network deletes.
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
