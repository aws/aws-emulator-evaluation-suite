"""op-contract-describe-traffic-mirror-filters-notfound-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-traffic-mirror-filters-notfound-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrafficMirrorFilters returns a created filter with its ID and Description, and an unknown
    filter ID fails with InvalidTrafficMirrorFilterId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    description = ctx.unique_name("sim2real-behav-tmf-")
    filter_id = ec2.create_traffic_mirror_filter(
        Description=description,
        TagSpecifications=[
            {"ResourceType": "traffic-mirror-filter", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    resp = ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[filter_id])
    filters = resp["TrafficMirrorFilters"]
    assert len(filters) == 1, f"expected exactly 1 filter for {filter_id!r}, got {len(filters)}"
    assert filters[0]["TrafficMirrorFilterId"] == filter_id, (
        f"expected TrafficMirrorFilterId {filter_id!r}, got {filters[0]['TrafficMirrorFilterId']!r}"
    )
    assert filters[0]["Description"] == description, (
        f"expected Description {description!r}, got {filters[0]['Description']!r}"
    )

    # Error boundary: syntactically valid but nonexistent ID.
    fake_id = "tmf-ffffffffffffffff"
    code, message = _error(
        lambda: ec2.describe_traffic_mirror_filters(TrafficMirrorFilterIds=[fake_id])
    )
    assert code == "InvalidTrafficMirrorFilterId.NotFound", f"expected NotFound, got {code!r}"
    assert message == f"{fake_id} does not exist", message


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
