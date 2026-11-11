"""tag-resource-round-trip-list-and-untag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-round-trip-list-and-untag"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource; UntagResource removes
    exactly the requested keys and leaves the rest untouched. DeleteStage then removes the
    tagging surface itself: GetStage and TagResource on the dead arn both report it gone."""
    client = ctx.client("ivs-realtime")
    stage_arn = client.create_stage(
        name=ctx.unique_name("sim2real-stage"), tags={"team": "blue"}
    )["stage"]["arn"]

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            client.delete_stage(arn=stage_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    initial_tags = client.list_tags_for_resource(resourceArn=stage_arn)["tags"]
    assert initial_tags == {"team": "blue"}, initial_tags

    client.tag_resource(resourceArn=stage_arn, tags={"env": "sim2real", "owner": "qa"})
    merged_tags = client.list_tags_for_resource(resourceArn=stage_arn)["tags"]
    assert merged_tags == {"team": "blue", "env": "sim2real", "owner": "qa"}, merged_tags

    client.untag_resource(resourceArn=stage_arn, tagKeys=["owner"])
    remaining_tags = client.list_tags_for_resource(resourceArn=stage_arn)["tags"]
    assert remaining_tags == {"team": "blue", "env": "sim2real"}, remaining_tags

    client.delete_stage(arn=stage_arn)
    get_code, get_message = _error(lambda: client.get_stage(arn=stage_arn))
    assert get_code == "ResourceNotFoundException", get_code
    assert get_message == f"Resource: {stage_arn} not found", get_message
    tag_code, tag_message = _error(lambda: client.tag_resource(resourceArn=stage_arn, tags={"x": "y"}))
    assert tag_code == "NotFoundException", tag_code
    assert tag_message == "Resource was not found", tag_message


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts what AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
