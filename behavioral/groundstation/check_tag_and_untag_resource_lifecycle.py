"""tag-and-untag-resource-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-lifecycle"
GROUP = "state"
SERVICES = ["groundstation"]


def _client_error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _tolerate_not_found(fn):
    """Run a cleanup delete; the check may already have deleted the resource."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags shown by ListTagsForResource and UntagResource removes only the given
    keys; after the config is deleted TagResource raises NotFoundException ("Resource was not
    found").
    """
    gs = ctx.client("groundstation")
    created = gs.create_config(
        name=ctx.unique_name("sim2real-gs-tag-"),
        configData={"trackingConfig": {"autotrack": "PREFERRED"}},
        tags={"initial": "yes"},
    )
    config_id, config_type, arn = created["configId"], created["configType"], created["configArn"]
    ctx.on_cleanup(lambda: _tolerate_not_found(
        lambda: gs.delete_config(configId=config_id, configType=config_type)))

    tags_after_create = gs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_create == {"initial": "yes"}, (
        f"expected {{'initial': 'yes'}} right after CreateConfig with tags=, got {tags_after_create!r}"
    )

    gs.tag_resource(resourceArn=arn, tags={"extra": "added"})
    tags_after_tag = gs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_tag == {"initial": "yes", "extra": "added"}, (
        f"expected TagResource to add 'extra' alongside the existing 'initial' tag, "
        f"got {tags_after_tag!r}"
    )

    gs.untag_resource(resourceArn=arn, tagKeys=["initial"])
    tags_after_untag = gs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after_untag == {"extra": "added"}, (
        f"expected UntagResource to remove exactly 'initial' and leave 'extra' untouched, "
        f"got {tags_after_untag!r}"
    )

    gs.delete_config(configId=config_id, configType=config_type)
    refused = _client_error(lambda: gs.tag_resource(resourceArn=arn, tags={"post-delete": "x"}))
    assert refused == ("NotFoundException", "Resource was not found"), (
        f"expected TagResource on a deleted Config's ARN to fail NotFoundException, got {refused!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
