"""create-describe-option-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-describe-option-group"
GROUP = 'option_groups'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOptionGroup -> DescribeOptionGroups returns the group."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-og-")
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral test option group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=name))
    resp = rds.describe_option_groups(OptionGroupName=name)
    groups = resp["OptionGroupsList"]
    assert len(groups) == 1
    assert groups[0]["OptionGroupName"] == name
    assert groups[0]["EngineName"] == "mysql"
    assert groups[0]["MajorEngineVersion"] == "8.0"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
