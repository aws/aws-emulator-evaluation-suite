"""update-group-fields-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-group-fields-persist"
GROUP = "state"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGroup persists a new Description, visible via GetGroup, without touching the query."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-update-")

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": '{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"sim2real-update-nomatch","Values":["' + name + '"]}]}',
    }
    rg.create_group(
        Name=name,
        Description="orig desc",
        ResourceQuery=query,
        Tags={"sim2real-check": "update-group-fields-persist"},
    )
    ctx.on_cleanup(lambda: rg.delete_group(Group=name))

    before = rg.get_group(Group=name)["Group"]
    assert before["Description"] == "orig desc", f"expected orig desc, got {before['Description']!r}"

    rg.update_group(Group=name, Description="new desc")

    after = rg.get_group(Group=name)["Group"]
    assert after["Description"] == "new desc", f"UpdateGroup did not persist: got {after['Description']!r}"

    # The query itself is untouched by UpdateGroup (only UpdateGroupQuery changes it).
    gq = rg.get_group_query(Group=name)["GroupQuery"]["ResourceQuery"]
    assert gq["Type"] == "TAG_FILTERS_1_0", f"UpdateGroup mutated the query type: got {gq['Type']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
