"""transit-gateway-cidr-add-remove-and-tag-filter-reflected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transit-gateway-cidr-add-remove-and-tag-filter-reflected"
GROUP = "transit-gateway"
SERVICES = ["ec2"]


def _poll_until(probe, predicate, *, timeout_s=240.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _tagged_ids(ec2, key: str, value: str) -> set[str]:
    ids: set[str] = set()
    paginator = ec2.get_paginator("describe_transit_gateways")
    for page in paginator.paginate(Filters=[{"Name": f"tag:{key}", "Values": [value]}]):
        ids.update(t["TransitGatewayId"] for t in page["TransitGateways"])
    return ids


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTransitGateway's add and remove of a CIDR block, and CreateTags/DeleteTags, each
    read back exactly through an independent DescribeTransitGateways and a tag:env filter."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(_teardown(
        lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id),
        "InvalidTransitGatewayID.NotFound",
    ))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        description=f"transit gateway {tgw_id} available",
    )

    added = ec2.modify_transit_gateway(
        TransitGatewayId=tgw_id,
        Options={"DnsSupport": "disable", "AddTransitGatewayCidrBlocks": ["10.100.0.0/16"]},
    )["TransitGateway"]["Options"]
    assert added["DnsSupport"] == "disable", f"expected DnsSupport disable, got {added.get('DnsSupport')!r}"
    assert added["TransitGatewayCidrBlocks"] == ["10.100.0.0/16"], (
        f"expected exactly ['10.100.0.0/16'] on the modify response, got {added['TransitGatewayCidrBlocks']!r}"
    )

    described = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
    assert described["Options"]["DnsSupport"] == "disable", (
        f"DescribeTransitGateways did not reflect DnsSupport disable, got {described['Options'].get('DnsSupport')!r}"
    )
    assert described["Options"]["TransitGatewayCidrBlocks"] == ["10.100.0.0/16"], (
        f"DescribeTransitGateways reported CIDR blocks {described['Options']['TransitGatewayCidrBlocks']!r}, "
        f"expected exactly ['10.100.0.0/16']"
    )

    removed = ec2.modify_transit_gateway(
        TransitGatewayId=tgw_id,
        Options={"RemoveTransitGatewayCidrBlocks": ["10.100.0.0/16"]},
    )["TransitGateway"]["Options"]
    assert removed.get("TransitGatewayCidrBlocks", []) == [], (
        f"expected no CIDR blocks on the modify response after removal, got {removed.get('TransitGatewayCidrBlocks')!r}"
    )

    described_after_remove = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
    assert described_after_remove["Options"].get("TransitGatewayCidrBlocks", []) == [], (
        f"DescribeTransitGateways still reports CIDR blocks after removal: "
        f"{described_after_remove['Options'].get('TransitGatewayCidrBlocks')!r}"
    )

    ec2.create_tags(Resources=[tgw_id], Tags=[{"Key": "env", "Value": "prod"}])
    described_tagged = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
    tag_map = {t["Key"]: t["Value"] for t in described_tagged.get("Tags", [])}
    assert tag_map.get("env") == "prod", f"expected env=prod tag on the gateway, got {tag_map!r}"
    filtered = _tagged_ids(ec2, "env", "prod")
    assert tgw_id in filtered, f"{tgw_id!r} not found via a tag:env=prod filter; filter returned {sorted(filtered)!r}"

    ec2.delete_tags(Resources=[tgw_id], Tags=[{"Key": "env"}])
    described_untagged = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
    tag_map_after = {t["Key"]: t["Value"] for t in described_untagged.get("Tags", [])}
    assert "env" not in tag_map_after, f"expected env tag removed, still present as {tag_map_after!r}"
    filtered_after = _tagged_ids(ec2, "env", "prod")
    assert tgw_id not in filtered_after, (
        f"{tgw_id!r} still returned by the tag:env=prod filter after DeleteTags: {sorted(filtered_after)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
