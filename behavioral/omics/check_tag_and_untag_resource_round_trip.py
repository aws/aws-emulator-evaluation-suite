"""tag-and-untag-resource-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-round-trip"
GROUP = "state"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and UntagResource add and remove single keys as ListTagsForResource shows; after the
    run group is deleted, GetRunGroup fails with ResourceNotFoundException and TagResource with
    ValidationException "Resource was not found"."""
    omics = ctx.client("omics")

    created = omics.create_run_group(
        requestId=ctx.unique_name("sim2real-tagreq-"),
        name=ctx.unique_name("sim2real-tagrg-"),
    )
    group_arn = created["arn"]
    group_id = created["id"]
    ctx.on_cleanup(lambda: _delete_run_group_if_present(ctx, group_id))

    omics.tag_resource(resourceArn=group_arn, tags={"sim2real-env": "test", "sim2real-team": "genomics"})
    tags_after_add = omics.list_tags_for_resource(resourceArn=group_arn)["tags"]
    assert tags_after_add.get("sim2real-env") == "test", (
        f"expected sim2real-env=test after TagResource, got {tags_after_add.get('sim2real-env')!r}"
    )
    assert tags_after_add.get("sim2real-team") == "genomics", (
        f"expected sim2real-team=genomics after TagResource, got {tags_after_add.get('sim2real-team')!r}"
    )

    omics.untag_resource(resourceArn=group_arn, tagKeys=["sim2real-env"])
    tags_after_remove = omics.list_tags_for_resource(resourceArn=group_arn)["tags"]
    assert "sim2real-env" not in tags_after_remove, (
        f"expected sim2real-env removed by UntagResource, still present: {tags_after_remove!r}"
    )
    assert tags_after_remove.get("sim2real-team") == "genomics", (
        "UntagResource of one key must not disturb an unrelated key, "
        f"got sim2real-team={tags_after_remove.get('sim2real-team')!r}"
    )

    omics.delete_run_group(id=group_id)

    try:
        omics.get_run_group(id=group_id)
    except ClientError as exc:
        get_code = exc.response["Error"]["Code"]
        get_message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"expected GetRunGroup on a deleted run group {group_id} to fail, but it succeeded")
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted run group, got {get_code!r}"
    )
    expected_get = f"Run group {group_id} not found"
    assert get_message == expected_get, f"expected message {expected_get!r}, got {get_message!r}"

    try:
        omics.tag_resource(resourceArn=group_arn, tags={"sim2real-post-delete": "should-fail"})
    except ClientError as exc:
        tag_code = exc.response["Error"]["Code"]
        tag_message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"expected TagResource on a deleted run group {group_id} to fail, but it succeeded")
    # TagResource on an already-deleted run group's ARN
    # rejects with ValidationException, not ResourceNotFoundException like GetRunGroup above.
    assert tag_code == "ValidationException", (
        f"expected ValidationException tagging a deleted run group, got {tag_code!r}"
    )
    assert tag_message == "Resource was not found", (
        f"expected message 'Resource was not found', got {tag_message!r}"
    )


def _delete_run_group_if_present(ctx, group_id: str) -> None:
    """Teardown: the check deletes the run group itself, so a not-found here is the expected end state."""
    try:
        ctx.client("omics").delete_run_group(id=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
