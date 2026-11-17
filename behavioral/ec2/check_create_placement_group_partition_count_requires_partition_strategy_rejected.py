"""create-placement-group-partition-count-requires-partition-strategy-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-placement-group-partition-count-requires-partition-strategy-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePlacementGroup rejects PartitionCount on a cluster-strategy group, and accepts
    the identical PartitionCount on a partition-strategy group."""
    ec2 = ctx.client("ec2")
    cluster_name = ctx.unique_name("sim2real-behav-pg-cluster-")

    code, message = _error(
        lambda: ec2.create_placement_group(
            GroupName=cluster_name, Strategy="cluster", PartitionCount=3,
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message}"
    expected_message = "partition-count is only available with the 'partition' strategy."
    assert message == expected_message, f"unexpected message: {message!r}"

    # effect absent: the rejected call must not have created a group under that name.
    survivors = ec2.describe_placement_groups(
        Filters=[{"Name": "group-name", "Values": [cluster_name]}]
    )["PlacementGroups"]
    assert survivors == [], f"expected no placement group named {cluster_name!r}, got {survivors!r}"

    # positive control: the identical PartitionCount is accepted on a partition-strategy group.
    partition_name = ctx.unique_name("sim2real-behav-pg-partition-")
    created = ec2.create_placement_group(
        GroupName=partition_name,
        Strategy="partition",
        PartitionCount=3,
        TagSpecifications=[_tag_spec("placement-group", partition_name)],
    )["PlacementGroup"]
    ctx.on_cleanup(lambda: ec2.delete_placement_group(GroupName=partition_name))
    assert created["PartitionCount"] == 3, f"expected PartitionCount 3, got {created.get('PartitionCount')}"

    described = ec2.describe_placement_groups(GroupNames=[partition_name])["PlacementGroups"][0]
    assert described["PartitionCount"] == 3, (
        f"expected PartitionCount 3 on describe, got {described.get('PartitionCount')}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
