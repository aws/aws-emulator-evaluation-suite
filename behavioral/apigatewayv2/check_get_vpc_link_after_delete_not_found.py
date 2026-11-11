"""get-vpc-link-after-delete-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-vpc-link-after-delete-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteVpcLink, GetVpcLink and UpdateVpcLink on the id fail NotFoundException and the id
    is unlisted, while a never-deleted sibling VPC link stays retrievable throughout."""
    apigw = ctx.client("apigatewayv2")
    ec2 = ctx.client("ec2")

    subnet_ids = _default_subnet_ids(ec2, ctx=ctx)
    if not subnet_ids:
        raise AssertionError(
            "no default VPC subnets available in this account/region to create a VPC Link "
            "(needs a default VPC with at least one subnet; closeable by creating a dedicated "
            "VPC/subnet fixture instead of relying on the account default)"
        )

    control_name = ctx.unique_name("sim2real-behav-vpclink-ctrl-")
    control = apigw.create_vpc_link(
        Name=control_name, SubnetIds=subnet_ids, Tags={"sim2real-behav-check": CHECK}
    )
    control_id = control["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_vpc_link_if_present(apigw, control_id))
    _poll_until(
        lambda: apigw.get_vpc_link(VpcLinkId=control_id),
        lambda r: r["VpcLinkStatus"] in ("AVAILABLE", "FAILED"),
        timeout_s=600.0,
        interval_s=15.0,
    )

    name = ctx.unique_name("sim2real-behav-vpclink-")
    created = apigw.create_vpc_link(
        Name=name, SubnetIds=subnet_ids, Tags={"sim2real-behav-check": CHECK}
    )
    vpc_link_id = created["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_vpc_link_if_present(apigw, vpc_link_id))
    fetched_name = apigw.get_vpc_link(VpcLinkId=vpc_link_id)["Name"]
    assert fetched_name == name, f"expected freshly created vpc link name {name!r}, got {fetched_name!r}"

    final = _poll_until(
        lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id),
        lambda r: r["VpcLinkStatus"] in ("AVAILABLE", "FAILED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert final["VpcLinkStatus"] == "AVAILABLE", (
        f"vpc link reached {final['VpcLinkStatus']}: {final.get('VpcLinkStatusMessage')}"
    )

    apigw.delete_vpc_link(VpcLinkId=vpc_link_id)

    # DeleteVpcLink returns while the link reads DELETING; poll until the read stops succeeding.
    _poll_until(
        lambda: _vpc_link_status_or_error(apigw, vpc_link_id),
        lambda r: r[0] != "OK",
        timeout_s=120.0,
        interval_s=5.0,
    )
    final_code, final_message = _error(lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id))
    assert final_code == "NotFoundException", (
        f"GetVpcLink on a deleted id: expected NotFoundException, got {final_code!r}: {final_message!r}"
    )
    assert final_message == "Invalid Vpc Link identifier specified", (
        f"GetVpcLink on a deleted id: expected the exact message, got {final_message!r}"
    )

    # effect absent: the deleted link no longer appears in the list
    all_ids = [v["VpcLinkId"] for v in apigw.get_vpc_links().get("Items", [])]
    assert vpc_link_id not in all_ids, (
        f"deleted vpc link {vpc_link_id} still present in GetVpcLinks: {all_ids}"
    )

    # a mutation on the dead id also fails, not just a read
    update_code, update_message = _error(
        lambda: apigw.update_vpc_link(VpcLinkId=vpc_link_id, Name="sim2real-behav-dead-update")
    )
    assert update_code == "NotFoundException", (
        f"UpdateVpcLink on a deleted id: expected NotFoundException, got {update_code!r}: {update_message!r}"
    )
    assert update_message == "Invalid Vpc Link identifier specified", (
        f"UpdateVpcLink on a deleted id: expected the exact message, got {update_message!r}"
    )

    # positive control: the sibling link is unaffected and still retrievable
    control_fetched_id = apigw.get_vpc_link(VpcLinkId=control_id)["VpcLinkId"]
    assert control_fetched_id == control_id, (
        f"sibling vpc link {control_id} should remain retrievable after its sibling's delete, "
        f"got {control_fetched_id!r}"
    )


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _vpc_link_status_or_error(apigw, vpc_link_id):
    """("OK", status) while GetVpcLink succeeds, else the ClientError (code, message)."""
    from botocore.exceptions import ClientError

    try:
        return "OK", apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _delete_vpc_link_if_present(apigw, vpc_link_id):
    try:
        apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
    except apigw.exceptions.NotFoundException:
        pass


def _default_subnet_ids(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return []
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    return [s["SubnetId"] for s in subnets][:3]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
