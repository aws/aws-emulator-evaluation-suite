"""vpc-link-tags-unicode-round-trip."""
from __future__ import annotations

import time
from behavioral_harness import tags

CHECK = "vpc-link-tags-unicode-round-trip"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags with unicode keys/values applied at CreateVpcLink are returned byte-identical
    by GetVpcLink."""
    apigw = ctx.client("apigatewayv2")
    _, subnet_ids = _default_vpc_subnets(ctx, count=1)

    # apigatewayv2 tag restrictions allow letters/numbers/spaces representable in
    # UTF-8 plus ". : + = @ _ / -" — unicode *letters* (CJK, accented Latin,
    # Cyrillic) are fine, but symbols such as emoji are rejected. Exercise
    # several unicode scripts while staying inside the allowed character set.
    tags = {
        "\u540d\u524d": "\u30c6\u30b9\u30c8-\u5024",
        "caf\u00e9-key": "m\u00fcnchen-\u043c\u0438\u0440",
    }

    vpc_link = apigw.create_vpc_link(
        Name=ctx.unique_name("sim2real-behav-vpclink-"), SubnetIds=subnet_ids, Tags=tags
    )
    vpc_link_id = vpc_link["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_vpc_link_and_wait(apigw, vpc_link_id))

    assert vpc_link["Tags"] == tags, f"CreateVpcLink echoed {vpc_link.get('Tags')!r}, expected {tags!r}"

    got = apigw.get_vpc_link(VpcLinkId=vpc_link_id)
    assert got["Tags"] == tags, f"GetVpcLink returned {got.get('Tags')!r}, expected {tags!r}"


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


def _delete_vpc_link_and_wait(apigw, vpc_link_id, timeout_s=900.0, interval_s=15.0):
    """Delete an HTTP API VPC link and wait until it is gone, so its ENIs leave the subnets.

    A link still PENDING refuses the delete (BadRequestException); that is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    # The wait for the accepted delete gets its own window.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            apigw.get_vpc_link(VpcLinkId=vpc_link_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"VPC link {vpc_link_id} still exists {timeout_s:.0f}s after DeleteVpcLink")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
