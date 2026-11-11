"""list-vpc-links-reflects-created."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-vpc-links-reflects-created"
GROUP = "data-plane"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVpcLinks immediately reflects a newly created VpcLink and no longer lists it
    after DeleteVpcLink completes, and the deleted id 404s on a direct GetVpcLink."""
    apigw = ctx.client("apigatewayv2")
    _, subnet_ids = _default_vpc_subnets(ctx, count=1)

    vpc_link = apigw.create_vpc_link(
        Name=ctx.unique_name("sim2real-behav-vpclink-"), SubnetIds=subnet_ids, Tags=TAGS
    )
    vpc_link_id = vpc_link["VpcLinkId"]

    def _cleanup():
        try:
            apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    ids = {item["VpcLinkId"] for item in _list_all_vpc_links(apigw)}
    assert vpc_link_id in ids, f"expected {vpc_link_id} in GetVpcLinks Items, got {ids!r}"

    # A VpcLink must finish provisioning (PENDING -> AVAILABLE) before it can be
    # deleted; deleting while PENDING is rejected with BadRequestException.
    def _status():
        return apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]

    _poll_until(_status, lambda s: s in ("AVAILABLE", "FAILED"), timeout_s=300, interval_s=10)

    apigw.delete_vpc_link(VpcLinkId=vpc_link_id)

    def _still_listed():
        ids_now = {item["VpcLinkId"] for item in _list_all_vpc_links(apigw)}
        return vpc_link_id in ids_now

    _poll_until(_still_listed, lambda listed: not listed, timeout_s=300, interval_s=10)

    def _still_readable():
        from botocore.exceptions import ClientError

        try:
            apigw.get_vpc_link(VpcLinkId=vpc_link_id)
            return True
        except ClientError:
            return False

    _poll_until(_still_readable, lambda readable: not readable, timeout_s=120, interval_s=5)

    code, message = _error(lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id))
    assert code == "NotFoundException", (
        f"expected NotFoundException reading deleted VpcLink {vpc_link_id!r}, got {code!r}: {message!r}"
    )
    assert message == "Invalid Vpc Link identifier specified", (
        f"unexpected NotFoundException message reading deleted VpcLink {vpc_link_id!r}: {message!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _default_vpc_subnets(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to source subnets for a VPC link")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < count:
        raise AssertionError(f"shared network has fewer than {count} subnets available for a VPC link")
    return vpc_id, [s["SubnetId"] for s in subnets[:count]]


def _list_all_vpc_links(apigw):
    items = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = apigw.get_vpc_links(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
