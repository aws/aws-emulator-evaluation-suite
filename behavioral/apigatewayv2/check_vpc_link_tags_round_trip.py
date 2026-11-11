"""vpc-link-tags-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "vpc-link-tags-round-trip"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied at CreateVpcLink time are returned as an exact key/value map via
    GetVpcLink, with no casing or ordering mutation."""
    subnet_ids = _default_subnet_ids(ctx)
    if not subnet_ids:
        raise AssertionError(
            "no default-VPC subnets found in this account/region to attach a VPC Link to; "
            "a default VPC (or an explicitly provisioned VPC+subnet) is required to close this gap."
        )

    apigw = ctx.client("apigatewayv2")
    name = ctx.unique_name("sim2real-vpclink-")
    tags = {
        "sim2real-Owner": "behavioral-suite",
        "Environment": "Test",
        "MixedCase-Key": "MixedCaseValue",
    }
    created = apigw.create_vpc_link(Name=name, SubnetIds=subnet_ids, Tags=tags)
    vpc_link_id = created["VpcLinkId"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_vpc_link(VpcLinkId=vpc_link_id)))

    assert created.get("Tags") == tags, created.get("Tags")

    fetched = apigw.get_vpc_link(VpcLinkId=vpc_link_id)
    assert fetched["Tags"] == tags, fetched["Tags"]

    # DeleteVpcLink rejects a link that is still PENDING with BadRequestException,
    # and the cleanup lambda above swallows that rejection -- without waiting for a
    # terminal state here first, cleanup silently fails on every run and the link
    # (and its AWS-managed ENIs) leaks. Drive it to AVAILABLE/FAILED before the body
    # ends so the delete cleanup registered above can actually succeed.
    final = _poll_until(
        lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id),
        lambda r: r["VpcLinkStatus"] in ("AVAILABLE", "FAILED"),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert final["VpcLinkStatus"] == "AVAILABLE", (
        f"vpc link reached {final['VpcLinkStatus']}: {final.get('VpcLinkStatusMessage')}"
    )
    assert final["Tags"] == tags, final["Tags"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _default_subnet_ids(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    seen_az = set()
    ids = []
    for subnet in resp.get("Subnets", []):
        az = subnet.get("AvailabilityZone")
        if az in seen_az:
            continue
        seen_az.add(az)
        ids.append(subnet["SubnetId"])
        if len(ids) >= 2:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
