"""op-contract-delete-placement-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-placement-group"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePlacementGroup removes an empty placement group and frees its name for
    reuse; deleting it again, or any other unknown placement group name, is rejected
    with InvalidPlacementGroup.Unknown."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-pg-")
    tag_spec = [{"ResourceType": "placement-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}]

    ec2.create_placement_group(GroupName=name, Strategy="cluster", TagSpecifications=tag_spec)
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_placement_group(GroupName=name)))

    described = ec2.describe_placement_groups(GroupNames=[name])["PlacementGroups"]
    assert len(described) == 1 and described[0]["State"] == "available", (
        f"expected exactly 1 available placement group, got {described}"
    )

    ec2.delete_placement_group(GroupName=name)

    code, message = _error(lambda: ec2.describe_placement_groups(GroupNames=[name]))
    assert code == "InvalidPlacementGroup.Unknown", f"unexpected error describing the deleted group: {code}: {message}"
    assert message == f"The Placement Group '{name}' is unknown.", message

    code, message = _error(lambda: ec2.delete_placement_group(GroupName=name))
    assert code == "InvalidPlacementGroup.Unknown", f"unexpected error on double-delete: {code}: {message}"
    assert message == f"The placement group '{name}' is unknown.", message

    bogus_name = ctx.unique_name("sim2real-behav-pg-nope-")
    code, message = _error(lambda: ec2.delete_placement_group(GroupName=bogus_name))
    assert code == "InvalidPlacementGroup.Unknown", f"unexpected error deleting an unknown group: {code}: {message}"
    assert message == f"The placement group '{bogus_name}' is unknown.", message

    recreated = ec2.create_placement_group(GroupName=name, Strategy="cluster", TagSpecifications=tag_spec)["PlacementGroup"]
    assert recreated["GroupName"] == name, f"freed name not reusable: {recreated}"


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPlacementGroup.Unknown":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
