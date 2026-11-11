"""delete-nonexistent-vpc-link-returns-notfound."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-nonexistent-vpc-link-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVpcLink on an already deleted vpcLinkId returns NotFoundException; the same
    link's first delete succeeding is the positive control."""
    apigw = ctx.client("apigateway")
    nlb_arn = _create_internal_nlb(ctx)

    name = ctx.unique_name("sim2real-novpclnk-")
    created = apigw.create_vpc_link(name=name, targetArns=[nlb_arn])
    vpc_link_id = created["id"]
    ctx.on_cleanup(lambda: _teardown(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id)))

    # positive control: the vpc link really exists ...
    got = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert got["id"] == vpc_link_id

    # DeleteVpcLink rejects a link still in PENDING ("Cannot delete vpc link in
    # PENDING. Please try again later") — measured on real AWS, not assumed. Wait
    # for a terminal provisioning state (AVAILABLE or FAILED); which one it lands
    # on is a lifecycle concern covered elsewhere, not what this check is about.
    status = _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=200, interval_s=10,
    )
    assert status in ("AVAILABLE", "FAILED"), f"vpc link stuck in {status} past the wait budget"

    # ... and the first delete succeeds, now that it is out of PENDING.
    apigw.delete_vpc_link(vpcLinkId=vpc_link_id)

    # DeleteVpcLink is itself asynchronous — measured on real AWS: an immediate
    # repeat delete right after the first one returns success again,
    # not NotFoundException, because the id has not finished tearing down yet.
    # Wait for the teardown to actually land before treating "gone" as the
    # negative case.
    get_code, get_message = _wait_gone(apigw, vpc_link_id, timeout_s=60, interval_s=5)
    assert get_code == "NotFoundException", f"vpc link never tore down, last get code={get_code}"
    assert get_message == "Invalid Vpc Link identifier specified", get_message

    # negative: it is now truly gone, so a repeat delete is NotFoundException
    code, message = _client_error(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Vpc Link identifier specified", message


# ===== helpers =====
_GONE = frozenset({"NotFoundException", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"})
# A VPC link still PENDING refuses its delete with BadRequestException until it settles.
_BUSY = frozenset({"BadRequestException", "ConflictException", "TooManyRequestsException"})


def _teardown(fn):
    """Run one teardown call: a resource already gone is fine; a still-settling or throttled one
    is retried every 2 s for up to 120 s; any other error raises."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code not in _BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_gone(apigw, vpc_link_id, *, timeout_s, interval_s):
    """Poll GetVpcLink until it fails; return that (code, message), or raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.get_vpc_link(vpcLinkId=vpc_link_id)
        except ClientError as err:
            error = err.response["Error"]
            return error["Code"], error.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"vpc link {vpc_link_id} still readable {timeout_s}s after its delete")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _create_internal_nlb(ctx) -> str:
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    tag = ctx.unique_name("sim2real-apigw-nlb-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.224.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.224.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

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
            timeout_s=180, interval_s=2,
        )

    ctx.on_cleanup(_cleanup_nlb)

    # Deliberately NOT waiting here for the NLB's own "active" state: CreateVpcLink
    # accepts a target ARN whose load balancer is still provisioning, and the vpc
    # link's own PENDING -> AVAILABLE transition already covers that wait within
    # this check's shared 300s budget.
    return lb_arn


def _nlb_exists(elbv2, lb_arn: str) -> bool:
    try:
        elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        return False


# A load balancer in this VPC deletes asynchronously and leaves its ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. Teardown waits (bounded) for the
# ENIs, retries DependencyViolation in one window shared by the check's network deletes, then raises
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
