"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a meeting ARN shows both tags in ListTagsForResource; after DeleteMeeting,
    ListTagsForResource and TagResource on that ARN fail with BadRequestException
    "Invalid meeting id" (not NotFoundException)."""
    chime = ctx.client("chime-sdk-meetings")
    meeting = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media region is a business parameter of the meeting, independent of ctx.region
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]
    meeting_id = meeting["MeetingId"]
    meeting_arn = meeting["MeetingArn"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    tags_to_apply = [{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-team", "Value": "behavioral"}]
    chime.tag_resource(ResourceARN=meeting_arn, Tags=tags_to_apply)

    listed = chime.list_tags_for_resource(ResourceARN=meeting_arn)["Tags"]
    listed_map = {t["Key"]: t["Value"] for t in listed}
    assert listed_map.get("sim2real-env") == "test", f"expected sim2real-env=test, got tags={listed_map!r}"
    assert listed_map.get("sim2real-team") == "behavioral", (
        f"expected sim2real-team=behavioral, got tags={listed_map!r}"
    )

    chime.delete_meeting(MeetingId=meeting_id)

    list_code, list_message = _client_error(lambda: chime.list_tags_for_resource(ResourceARN=meeting_arn))
    assert list_code == "BadRequestException", (
        f"expected ListTagsForResource on a deleted meeting to be BadRequestException, got {list_code!r}"
    )
    assert list_message == "Invalid meeting id", f"got message={list_message!r}"

    tag_code, tag_message = _client_error(
        lambda: chime.tag_resource(ResourceARN=meeting_arn, Tags=[{"Key": "sim2real-late", "Value": "1"}])
    )
    assert tag_code == "BadRequestException", (
        f"expected TagResource on a deleted meeting to be BadRequestException, got {tag_code!r}"
    )
    assert tag_message == "Invalid meeting id", f"got message={tag_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
