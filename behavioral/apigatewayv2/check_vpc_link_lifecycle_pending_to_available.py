"""vpc-link-lifecycle-pending-to-available."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vpc-link-lifecycle-pending-to-available"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink starts PENDING, GetVpcLink polling shows transition to AVAILABLE,
    UpdateVpcLink modifies the name, DeleteVpcLink removes it and GetVpcLink 404s."""
    apigw = ctx.client("apigatewayv2")
    ec2 = ctx.client("ec2")

    subnet_ids = _default_subnet_ids(ec2, ctx=ctx)
    if not subnet_ids:
        raise AssertionError(
            "no default VPC subnets available in this account/region to create a VPC Link "
            "(needs a default VPC with at least one subnet; closeable by creating a dedicated "
            "VPC/subnet fixture instead of relying on the account default)"
        )

    name = ctx.unique_name("sim2real-behav-vpclink-")
    created = apigw.create_vpc_link(Name=name, SubnetIds=subnet_ids)
    vpc_link_id = created["VpcLinkId"]
    assert created["VpcLinkStatus"] in ("PENDING", "AVAILABLE"), (
        f"unexpected initial VpcLinkStatus: {created['VpcLinkStatus']!r}"
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: apigw.delete_vpc_link(VpcLinkId=vpc_link_id))
    )

    final = _poll_until(
        lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id),
        lambda r: r["VpcLinkStatus"] in ("AVAILABLE", "FAILED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert final["VpcLinkStatus"] == "AVAILABLE", (
        f"vpc link reached {final['VpcLinkStatus']}: {final.get('VpcLinkStatusMessage')}"
    )

    new_name = f"{name}-renamed"
    updated = apigw.update_vpc_link(VpcLinkId=vpc_link_id, Name=new_name)
    assert updated["Name"] == new_name, (
        f"UpdateVpcLink response Name mismatch: expected {new_name!r}, got {updated['Name']!r}"
    )
    reread = apigw.get_vpc_link(VpcLinkId=vpc_link_id)
    assert reread["Name"] == new_name, (
        f"GetVpcLink after rename Name mismatch: expected {new_name!r}, got {reread['Name']!r}"
    )

    apigw.delete_vpc_link(VpcLinkId=vpc_link_id)

    final = _poll_until(
        lambda: _read_outcome(lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id)),
        lambda outcome: "error" in outcome,
        timeout_s=120.0,
        interval_s=5.0,
    )
    final_code = final["error"].get("Code")
    assert final_code == "NotFoundException", (
        f"expected NotFoundException reading a deleted vpc link, got {final_code!r}"
    )
    expected_message = "Invalid Vpc Link identifier specified"
    assert final["error"].get("Message") == expected_message, (
        f"expected {expected_message!r}, got {final['error'].get('Message')!r}"
    )

    mutate_after_delete_code, mutate_message = _error_code(
        lambda: apigw.update_vpc_link(VpcLinkId=vpc_link_id, Name="should-not-apply")
    )
    assert mutate_after_delete_code == "NotFoundException", (
        f"expected NotFoundException mutating a deleted vpc link, got {mutate_after_delete_code!r}"
    )
    expected_message = "Invalid Vpc Link identifier specified"
    assert mutate_message == expected_message, f"expected {expected_message!r}, got {mutate_message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _read_outcome(fn):
    """Call fn(); return {"result": ...} on success or {"error": <botocore Error dict>}."""
    from botocore.exceptions import ClientError

    try:
        return {"result": fn()}
    except ClientError as e:
        return {"error": e.response["Error"]}


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


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
