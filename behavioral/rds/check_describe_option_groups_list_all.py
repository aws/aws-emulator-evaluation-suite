"""describe-option-groups-list-all."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "describe-option-groups-list-all"
GROUP = 'option_groups'
SERVICES = ['rds']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeOptionGroups with no name returns the whole catalog: implicit defaults
    spanning multiple engines, each with a well-formed representation."""
    rds = ctx.client("rds")
    resp = rds.describe_option_groups()
    groups = resp["OptionGroupsList"]
    assert len(groups) > 1, f"expected multiple catalog option groups, got {groups}"

    engines = {g["EngineName"] for g in groups}
    assert len(engines) > 1, f"expected the unfiltered list to span multiple engines, got {engines}"

    for g in groups:
        assert g["OptionGroupName"], g
        assert g["EngineName"], g
        assert g["MajorEngineVersion"], g
        assert g["OptionGroupArn"].endswith(":og:" + g["OptionGroupName"]), g["OptionGroupArn"]
        assert isinstance(g["AllowsVpcAndNonVpcInstanceMemberships"], bool), g


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
