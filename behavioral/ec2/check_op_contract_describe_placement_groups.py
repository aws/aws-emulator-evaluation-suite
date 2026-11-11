"""op-contract-describe-placement-groups."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-placement-groups"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePlacementGroups returns a created cluster group with its ID; an unknown name fails with
    InvalidPlacementGroup.Unknown, and after delete both a describe and a repeat delete of the group
    fail with that code (exact messages)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-pg-")

    create_resp = ec2.create_placement_group(
        GroupName=name,
        Strategy="cluster",
        TagSpecifications=[{"ResourceType": "placement-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    group_id = create_resp["PlacementGroup"]["GroupId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_already_gone(lambda: ec2.delete_placement_group(GroupName=name)))

    # Success path
    desc = ec2.describe_placement_groups(GroupNames=[name])
    groups = desc["PlacementGroups"]
    assert len(groups) == 1, f"expected exactly 1 placement group, got {len(groups)}"
    pg = groups[0]
    assert pg["GroupName"] == name
    assert pg["GroupId"] == group_id
    assert pg["Strategy"] == "cluster"
    assert pg["State"] in ("pending", "available")

    # Error boundary: an unknown placement group name is a distinct, named
    # error - not a generic ValidationError and not an empty result set.
    bogus_name = ctx.unique_name("sim2real-behav-pg-missing-")
    code, message = _error(lambda: ec2.describe_placement_groups(GroupNames=[bogus_name]))
    assert code == "InvalidPlacementGroup.Unknown", f"expected InvalidPlacementGroup.Unknown, got {code}"
    assert message == f"The Placement Group '{bogus_name}' is unknown.", message

    # After delete, a describe by the group's name and a repeated delete both fail with the same
    # not-found code.
    ec2.delete_placement_group(GroupName=name)
    gone_code, gone_message = _error(lambda: ec2.describe_placement_groups(GroupNames=[name]))
    assert gone_code == "InvalidPlacementGroup.Unknown", f"expected InvalidPlacementGroup.Unknown after delete, got {gone_code}"
    assert gone_message == f"The Placement Group '{name}' is unknown.", gone_message
    redelete_code, redelete_message = _error(lambda: ec2.delete_placement_group(GroupName=name))
    assert redelete_code == "InvalidPlacementGroup.Unknown", f"expected InvalidPlacementGroup.Unknown on re-delete, got {redelete_code}"
    assert redelete_message == f"The placement group '{name}' is unknown.", redelete_message


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _cleanup_ignore_already_gone(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPlacementGroup.Unknown":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
