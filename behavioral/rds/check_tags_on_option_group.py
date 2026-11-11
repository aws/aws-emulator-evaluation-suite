"""tags-on-option-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tags-on-option-group"
GROUP = 'tags'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags work on option groups too (verifies ARN-based tagging generality)."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-og-")
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral test option group",
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=name))
    resp = rds.describe_option_groups(OptionGroupName=name)
    arn = resp["OptionGroupsList"][0]["OptionGroupArn"]
    rds.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": "service", "Value": "rds-test"}])
    tag_resp = rds.list_tags_for_resource(ResourceName=arn)
    assert tag_resp["TagList"] == [{"Key": "service", "Value": "rds-test"}], (
        f"expected exactly [{{'Key': 'service', 'Value': 'rds-test'}}], got {tag_resp['TagList']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
