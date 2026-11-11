"""list-hosted-zones-private-type-filter-lists-only-private-zones."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-hosted-zones-private-type-filter-lists-only-private-zones"
GROUP = "hosted-zones"
SERVICES = ["route53"]


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _listed(route53, **kwargs):
    """Every hosted zone id ListHostedZones returns with these filters, following the marker."""
    ids, marker = [], None
    for _ in range(100):
        page = route53.list_hosted_zones(**kwargs, **({"Marker": marker} if marker else {}))
        ids += [z["Id"] for z in page["HostedZones"]]
        if not page.get("IsTruncated"):
            return ids
        marker = page["NextMarker"]
    raise AssertionError("ListHostedZones did not finish within 100 pages")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHostedZones with HostedZoneType=PrivateHostedZone lists a private zone this check created
    and not its public twin, while the unfiltered listing has both; an unknown type is refused.
    """
    route53 = ctx.client("route53")
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    name = f"{ctx.unique_name('sim2real-behav-')}.example.test."
    private = route53.create_hosted_zone(
        Name=name, CallerReference=str(uuid.uuid4()),
        VPC={"VPCRegion": ctx.region, "VPCId": vpc},
        HostedZoneConfig={"Comment": "sim2real private", "PrivateZone": True},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=private))
    public = route53.create_hosted_zone(
        Name=name, CallerReference=str(uuid.uuid4()),
        HostedZoneConfig={"Comment": "sim2real public", "PrivateZone": False},
    )["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: route53.delete_hosted_zone(Id=public))

    everything = _listed(route53)
    assert {private, public} <= set(everything), (
        f"the unfiltered listing must hold both zones; missing {sorted({private, public} - set(everything))}"
    )
    privates = _listed(route53, HostedZoneType="PrivateHostedZone")
    assert private in privates, f"the private zone {private} is missing from the private listing"
    assert public not in privates, f"the public zone {public} appears in the private listing"

    code, message = _error(lambda: route53.list_hosted_zones(HostedZoneType="SharedHostedZone"))
    assert code == "InvalidInput", f"an unknown HostedZoneType: got {code}: {message!r}"
    expected = (
        "1 validation error detected: Value 'SharedHostedZone' at 'hostedZoneType' failed to "
        "satisfy constraint: Member must satisfy enum value set: [PrivateHostedZone]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
