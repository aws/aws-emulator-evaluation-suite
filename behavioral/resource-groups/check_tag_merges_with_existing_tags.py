"""tag-merges-with-existing-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-merges-with-existing-tags"
GROUP = "tagging"
SERVICES = ["resource-groups"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag() merges new keys into the existing tag set instead of replacing it wholesale."""
    rg = ctx.client("resource-groups")
    name = ctx.unique_name("sim2real-rg-tagmerge-")

    query = {
        "Type": "TAG_FILTERS_1_0",
        "Query": '{"ResourceTypeFilters":["AWS::AllSupported"],"TagFilters":[{"Key":"sim2real-tagmerge-nomatch","Values":["' + name + '"]}]}',
    }
    created = rg.create_group(Name=name, ResourceQuery=query, Tags={"Alpha": "1"})
    arn = created["Group"]["GroupArn"]
    ctx.on_cleanup(lambda: rg.delete_group(Group=name))

    tags0 = rg.get_tags(Arn=arn)["Tags"]
    assert tags0 == {"Alpha": "1"}, f"expected only the CreateGroup tag {{'Alpha': '1'}}, got {tags0}"

    rg.tag(Arn=arn, Tags={"Beta": "2"})
    tags1 = rg.get_tags(Arn=arn)["Tags"]
    assert tags1 == {"Alpha": "1", "Beta": "2"}, (
        f"expected Tag() to merge Beta into the existing Alpha tag, got {tags1}"
    )

    # Overwriting one key must not drop the other (partial merge, not a full replace).
    rg.tag(Arn=arn, Tags={"Alpha": "99"})
    tags2 = rg.get_tags(Arn=arn)["Tags"]
    assert tags2 == {"Alpha": "99", "Beta": "2"}, (
        f"expected Tag() to overwrite Alpha in place and leave Beta untouched, got {tags2}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
