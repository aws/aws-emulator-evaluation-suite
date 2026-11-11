"""tags-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

PARAM_FAMILY = "redshift-1.0"

CHECK = "tags-lifecycle"
GROUP = 'tagging'
SERVICES = ['redshift']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags/DescribeTags/DeleteTags: tags are keyed per resource ARN and delete is per-key."""
    rs = ctx.client("redshift")
    account = ctx.client("sts").get_caller_identity()["Account"]
    group_name = ctx.unique_name("sim2real-behav-rs-tagpg-")
    ctx.on_cleanup(lambda: rs.delete_cluster_parameter_group(ParameterGroupName=group_name))
    rs.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily=PARAM_FAMILY,
        Description="behavioral fidelity tagging check",
    )
    resource_arn = f"arn:aws:redshift:{ctx.region}:{account}:parametergroup:{group_name}"

    rs.create_tags(
        ResourceName=resource_arn,
        Tags=[{"Key": "sim2real-behav", "Value": "true"}, {"Key": "phase", "Value": "one"}],
    )
    tagged = rs.describe_tags(ResourceName=resource_arn)["TaggedResources"]
    tags = {t["Tag"]["Key"]: t["Tag"]["Value"] for t in tagged}
    assert tags == {"sim2real-behav": "true", "phase": "one"}, tags
    assert {t["ResourceType"] for t in tagged} == {"parametergroup"}, tagged

    # Re-tagging an existing key overwrites the value rather than duplicating it.
    rs.create_tags(ResourceName=resource_arn, Tags=[{"Key": "phase", "Value": "two"}])
    tags = {
        t["Tag"]["Key"]: t["Tag"]["Value"]
        for t in rs.describe_tags(ResourceName=resource_arn)["TaggedResources"]
    }
    assert tags == {"sim2real-behav": "true", "phase": "two"}, tags

    rs.delete_tags(ResourceName=resource_arn, TagKeys=["phase"])
    tags = {
        t["Tag"]["Key"]: t["Tag"]["Value"]
        for t in rs.describe_tags(ResourceName=resource_arn)["TaggedResources"]
    }
    assert tags == {"sim2real-behav": "true"}, f"delete must remove only the named key, got {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
