"""create-group-query-success."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-group-query-success"
GROUP = "state"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroup with a TAG_FILTERS_1_0 ResourceQuery persists and echoes back via GetGroupQuery."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-")
    marker = name

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": json.dumps(
            {
                "ResourceTypeFilters": ["AWS::AllSupported"],
                "TagFilters": [{"Key": "sim2real-rg-marker", "Values": [marker]}],
            }
        ),
    }
    resp = rg.create_group(
        Name=name,
        Description="sim2real behavioral fidelity check group",
        ResourceQuery=query,
        Tags={"sim2real-rg-marker": marker},
    )
    ctx.on_cleanup(lambda: rg.delete_group(Group=name))

    assert resp["Group"]["Name"] == name, f"expected group name {name!r}, got {resp['Group']['Name']!r}"
    assert name in resp["Group"]["GroupArn"], f"expected {name!r} in arn, got {resp['Group']['GroupArn']!r}"
    assert resp["ResourceQuery"]["Type"] == "TAG_FILTERS_1_0", (
        f"expected query type TAG_FILTERS_1_0, got {resp['ResourceQuery']['Type']!r}"
    )

    gq = rg.get_group_query(Group=name)["GroupQuery"]
    assert gq["GroupName"] == name, f"expected GetGroupQuery group name {name!r}, got {gq['GroupName']!r}"
    assert gq["ResourceQuery"]["Type"] == "TAG_FILTERS_1_0", (
        f"expected persisted query type TAG_FILTERS_1_0, got {gq['ResourceQuery']['Type']!r}"
    )
    parsed = json.loads(gq["ResourceQuery"]["Query"])
    assert parsed["TagFilters"][0]["Key"] == "sim2real-rg-marker", (
        f"expected persisted tag filter key 'sim2real-rg-marker', got {parsed['TagFilters'][0]['Key']!r}"
    )
    assert parsed["TagFilters"][0]["Values"] == [marker], (
        f"expected persisted tag filter values {[marker]!r}, got {parsed['TagFilters'][0]['Values']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
