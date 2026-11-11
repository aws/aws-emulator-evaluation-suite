"""tag-resource-reserved-aws-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-rejected"
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


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) ``fn`` raises. An unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """A sink refuses TagResource and UntagResource on a key in the reserved ``aws:`` namespace,
    matched case-insensitively, with distinct BadRequestException messages, and its tag set stays
    unchanged in GetSink and ListTagsForResource; an ordinary key is accepted right after.
    """
    oam = ctx.client("oam")
    name = ctx.unique_name("sim2real-behav-oam-sink-")
    arn = oam.create_sink(Name=name, Tags={"origin": "create"})["Arn"]
    ctx.on_cleanup(_teardown(lambda: oam.delete_sink(Identifier=arn), "ResourceNotFoundException"))

    code, msg = _error(lambda: oam.tag_resource(ResourceArn=arn, Tags={"AWS:sim2real": "v"}))
    assert (code, msg) == (
        "BadRequestException",
        "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)",
    ), f"TagResource with an AWS:-prefixed key gave {(code, msg)!r}"

    code, msg = _error(lambda: oam.untag_resource(ResourceArn=arn, TagKeys=["aws:sim2real"]))
    assert (code, msg) == (
        "BadRequestException",
        "Invalid tag key. Customers cannot remove tag keys starting with aws: (case insensitive)",
    ), f"UntagResource of an aws:-prefixed key gave {(code, msg)!r}"

    unchanged = {
        "get_sink": oam.get_sink(Identifier=arn, IncludeTags=True).get("Tags"),
        "list_tags": oam.list_tags_for_resource(ResourceArn=arn)["Tags"],
    }
    want = {"origin": "create"}
    assert unchanged == {"get_sink": want, "list_tags": want}, (
        f"the refused calls changed the tag set: {unchanged!r}"
    )

    # Positive control: an ordinary key on the same sink is accepted and visible.
    oam.tag_resource(ResourceArn=arn, Tags={"team": "observability"})
    after = oam.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after == {"origin": "create", "team": "observability"}, (
        f"an ordinary TagResource after the refusals left tags {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
