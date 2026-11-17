"""tag-operations-on-nonexistent-cluster-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-operations-on-nonexistent-cluster-arn-rejected"
GROUP = "tags"
SERVICES = ["rds"]

ERR_CLUSTER_NOT_FOUND = "DBClusterNotFoundFault"


def _error_code(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource, AddTagsToResource and RemoveTagsFromResource each reject a
    well-formed DB cluster ARN naming an identifier that was never created, with
    DBClusterNotFoundFault; the identical calls succeed against a subnet group this check made."""
    rds = ctx.client("rds")
    bogus_cluster_id = ctx.unique_name("sim2real-behav-clus-")
    bogus_arn = f"arn:aws:rds:{ctx.region}:{ctx.account}:cluster:{bogus_cluster_id}"

    list_code, list_message = _error_code(lambda: rds.list_tags_for_resource(ResourceName=bogus_arn))
    assert list_code == ERR_CLUSTER_NOT_FOUND, f"unexpected error code: {list_code!r}"
    expected = f"Could not find a DB Cluster matching the resource name: {bogus_arn}"
    assert list_message == expected, f"unexpected message: {list_message!r} (expected {expected!r})"

    add_code, add_message = _error_code(
        lambda: rds.add_tags_to_resource(
            ResourceName=bogus_arn, Tags=[{"Key": "sim2real-probe", "Value": "x"}]
        )
    )
    assert add_code == ERR_CLUSTER_NOT_FOUND, f"unexpected error code: {add_code!r}"
    assert add_message == expected, f"unexpected message: {add_message!r} (expected {expected!r})"

    remove_code, remove_message = _error_code(
        lambda: rds.remove_tags_from_resource(ResourceName=bogus_arn, TagKeys=["sim2real-probe"])
    )
    assert remove_code == ERR_CLUSTER_NOT_FOUND, f"unexpected error code: {remove_code!r}"
    assert remove_message == expected, f"unexpected message: {remove_message!r} (expected {expected!r})"

    # Positive control: the identical operations succeed against a real resource.
    subnet_group = ctx.unique_name("sim2real-behav-dbsg-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription="sim2real positive control",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group))
    described = rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group)["DBSubnetGroups"]
    real_arn = described[0]["DBSubnetGroupArn"]

    rds.add_tags_to_resource(ResourceName=real_arn, Tags=[{"Key": "sim2real-probe", "Value": "x"}])
    real_tags = {t["Key"]: t["Value"] for t in rds.list_tags_for_resource(ResourceName=real_arn)["TagList"]}
    assert real_tags.get("sim2real-probe") == "x", (
        f"expected the tag added to the real subnet group to read back, got {real_tags!r}"
    )
    rds.remove_tags_from_resource(ResourceName=real_arn, TagKeys=["sim2real-probe"])
    after_remove = {t["Key"]: t["Value"] for t in rds.list_tags_for_resource(ResourceName=real_arn)["TagList"]}
    assert "sim2real-probe" not in after_remove, (
        f"expected sim2real-probe removed from the real subnet group, got {after_remove!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
