"""get-sink-include-tags-tracks-tag-and-untag."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sink-include-tags-tracks-tag-and-untag"
GROUP = 'tagging'
SERVICES = ['oam']


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """GetSink's tags with IncludeTags=True or omitted equal ListTagsForResource after each TagResource
    and UntagResource, down to empty, and IncludeTags=False omits Tags while keeping Arn and Name."""
    oam = ctx.client("oam")
    name = ctx.unique_name("sim2real-behav-oam-sink-")
    sink = oam.create_sink(Name=name, Tags={"origin": "create"})
    arn = sink["Arn"]
    ctx.on_cleanup(_teardown(lambda: oam.delete_sink(Identifier=arn), "ResourceNotFoundException"))
    assert sink.get("Tags") == {"origin": "create"}, f"CreateSink echoed tags {sink.get('Tags')!r}"

    def _observed() -> dict:
        included = oam.get_sink(Identifier=arn, IncludeTags=True)
        default = oam.get_sink(Identifier=arn)
        listed = oam.list_tags_for_resource(ResourceArn=arn)["Tags"]
        return {
            "include_true": included.get("Tags"),
            "include_omitted": default.get("Tags"),
            "list_tags": listed,
        }

    def _expect(want: dict, after: str) -> None:
        got = _observed()
        assert got == {"include_true": want, "include_omitted": want, "list_tags": want}, (
            f"after {after}, expected every view to report {want!r}, got {got!r}"
        )

    _expect({"origin": "create"}, "CreateSink")

    oam.tag_resource(ResourceArn=arn, Tags={"team": "observability"})
    _expect({"origin": "create", "team": "observability"}, "TagResource")

    oam.untag_resource(ResourceArn=arn, TagKeys=["origin"])
    _expect({"team": "observability"}, "UntagResource of the create-time tag")

    excluded = oam.get_sink(Identifier=arn, IncludeTags=False)
    assert "Tags" not in excluded, (
        f"GetSink IncludeTags=False still returned Tags {excluded.get('Tags')!r}"
    )
    assert (excluded["Arn"], excluded["Name"]) == (arn, name), (
        f"GetSink IncludeTags=False returned a different sink: name {excluded.get('Name')!r}"
    )

    oam.untag_resource(ResourceArn=arn, TagKeys=["team"])
    _expect({}, "UntagResource of the last tag")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
