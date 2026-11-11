"""tag-resource-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "control-plane"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource on a collaboration ARN actually persists and
    removes tags, as observed through ListTagsForResource."""
    cr = ctx.client("cleanrooms")

    collab = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
    )["collaboration"]
    collab_id = collab["id"]
    collab_arn = collab["arn"]
    ctx.on_cleanup(lambda: cr.delete_collaboration(collaborationIdentifier=collab_id))

    empty = cr.list_tags_for_resource(resourceArn=collab_arn)["tags"]
    assert empty == {}, f"expected no tags on a freshly created collaboration, got {empty!r}"

    cr.tag_resource(resourceArn=collab_arn, tags={"env": "sim2real", "purpose": "behavioral-check"})
    after_tag = cr.list_tags_for_resource(resourceArn=collab_arn)["tags"]
    assert after_tag == {"env": "sim2real", "purpose": "behavioral-check"}, (
        f"expected {{'env': 'sim2real', 'purpose': 'behavioral-check'}} after TagResource, got {after_tag!r}"
    )

    cr.untag_resource(resourceArn=collab_arn, tagKeys=["purpose"])
    after_untag = cr.list_tags_for_resource(resourceArn=collab_arn)["tags"]
    assert after_untag == {"env": "sim2real"}, (
        f"expected {{'env': 'sim2real'}} after UntagResource(['purpose']), got {after_untag!r}"
    )

    error = _error(lambda: cr.tag_resource(
        resourceArn=collab_arn.replace(collab_id, "00000000-0000-0000-0000-000000000000"),
        tags={"x": "y"},
    ))
    # Empirically the tagging API surfaces a distinct NotFoundException (not
    # the ResourceNotFoundException used by the core CleanRooms CRUD APIs).
    assert error["Code"] == "NotFoundException", f"expected NotFoundException, got {error!r}"
    assert error["Message"] == "Resource was not found", error


def _error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
