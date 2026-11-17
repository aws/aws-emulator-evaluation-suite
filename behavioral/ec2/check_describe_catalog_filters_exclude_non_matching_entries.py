"""describe-catalog-filters-exclude-non-matching-entries."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-catalog-filters-exclude-non-matching-entries"
GROUP = "reference-data"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAvailabilityZones, DescribeImages and DescribeVpcEndpointServices filters exclude
    non-matching entries: a zone-id/zone-name filter returns exactly one zone, an architecture
    filter yields disjoint id sets, and a ServiceNames filter returns only that service's details.
    """
    ec2 = ctx.client("ec2")

    _check_availability_zone_filters(ec2, ctx)
    _check_image_architecture_filters(ec2)
    _check_vpc_endpoint_service_filters(ec2, ctx)


def _check_availability_zone_filters(ec2, ctx) -> None:
    baseline = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert baseline, "expected at least one available availability zone"
    target = baseline[0]
    target_zone_id = target["ZoneId"]
    target_zone_name = target["ZoneName"]

    by_zone_id = ec2.describe_availability_zones(
        Filters=[{"Name": "zone-id", "Values": [target_zone_id]}]
    )["AvailabilityZones"]
    assert len(by_zone_id) == 1, (
        f"expected exactly one zone for zone-id={target_zone_id!r}, got {by_zone_id}"
    )
    assert by_zone_id[0]["ZoneName"] == target_zone_name, (
        f"expected ZoneName {target_zone_name!r} for zone-id={target_zone_id!r}, "
        f"got {by_zone_id[0]['ZoneName']!r}"
    )
    assert by_zone_id[0]["RegionName"] == ctx.region, (
        f"expected RegionName {ctx.region!r}, got {by_zone_id[0]['RegionName']!r}"
    )

    by_zone_name = ec2.describe_availability_zones(
        Filters=[{"Name": "zone-name", "Values": [target_zone_name]}]
    )["AvailabilityZones"]
    assert len(by_zone_name) == 1, (
        f"expected exactly one zone for zone-name={target_zone_name!r}, got {by_zone_name}"
    )
    assert by_zone_name[0]["ZoneId"] == target_zone_id, (
        f"expected ZoneId {target_zone_id!r} for zone-name={target_zone_name!r}, "
        f"got {by_zone_name[0]['ZoneId']!r}"
    )
    assert by_zone_name[0]["RegionName"] == ctx.region, (
        f"expected RegionName {ctx.region!r}, got {by_zone_name[0]['RegionName']!r}"
    )


def _check_image_architecture_filters(ec2) -> None:
    def _amazon_images(architecture: str) -> list[dict]:
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "architecture", "Values": [architecture]},
                {"Name": "virtualization-type", "Values": ["hvm"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "is-public", "Values": ["true"]},
            ],
        )["Images"]
        assert images, f"expected amazon-owned {architecture} images, got none"
        for img in images:
            image_id = img["ImageId"]
            assert img["Architecture"] == architecture, (
                f"{image_id}: expected Architecture={architecture!r}, got {img['Architecture']!r}"
            )
            assert img["VirtualizationType"] == "hvm", (
                f"{image_id}: expected VirtualizationType=hvm, got {img['VirtualizationType']!r}"
            )
            assert img["State"] == "available", (
                f"{image_id}: expected State=available, got {img['State']!r}"
            )
            assert img["Public"] is True, f"{image_id}: expected Public=True"
        return images

    arm64_images = _amazon_images("arm64")
    x86_64_images = _amazon_images("x86_64")

    arm64_ids = {img["ImageId"] for img in arm64_images}
    x86_64_ids = {img["ImageId"] for img in x86_64_images}
    overlap = arm64_ids & x86_64_ids
    assert not overlap, (
        f"expected disjoint image id sets for architecture=arm64 and architecture=x86_64, "
        f"got {sorted(overlap)!r} in both"
    )


def _check_vpc_endpoint_service_filters(ec2, ctx) -> None:
    s3_name = f"com.amazonaws.{ctx.region}.s3"
    ecr_name = f"com.amazonaws.{ctx.region}.ecr.api"

    s3_details = ec2.describe_vpc_endpoint_services(ServiceNames=[s3_name])["ServiceDetails"]
    assert s3_details, f"expected ServiceDetails for {s3_name}, got none"
    other_names = {d["ServiceName"] for d in s3_details if d["ServiceName"] != s3_name}
    assert not other_names, (
        f"ServiceNames=[{s3_name}] must return only {s3_name}, also got {sorted(other_names)!r}"
    )
    s3_types = {st["ServiceType"] for d in s3_details for st in d["ServiceType"]}
    assert s3_types == {"Gateway", "Interface"}, f"expected Gateway+Interface for {s3_name}, got {s3_types}"

    ecr_details = ec2.describe_vpc_endpoint_services(ServiceNames=[ecr_name])["ServiceDetails"]
    assert ecr_details, f"expected ServiceDetails for {ecr_name}, got none"
    other_names = {d["ServiceName"] for d in ecr_details if d["ServiceName"] != ecr_name}
    assert not other_names, (
        f"ServiceNames=[{ecr_name}] must return only {ecr_name}, also got {sorted(other_names)!r}"
    )
    ecr_types = {st["ServiceType"] for d in ecr_details for st in d["ServiceType"]}
    assert ecr_types == {"Interface"}, f"expected Interface-only for {ecr_name}, got {ecr_types}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
