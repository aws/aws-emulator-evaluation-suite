"""untag-resource-removes-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tags"
GROUP = "tagging"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named tag keys, leaving the rest of the
    resource's tags intact."""
    chime = ctx.client("chime-sdk-meetings")
    meeting = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]
    meeting_id = meeting["MeetingId"]
    meeting_arn = meeting["MeetingArn"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    chime.tag_resource(
        ResourceARN=meeting_arn,
        Tags=[{"Key": "sim2real-keep", "Value": "1"}, {"Key": "sim2real-drop", "Value": "2"}],
    )

    chime.untag_resource(ResourceARN=meeting_arn, TagKeys=["sim2real-drop"])

    listed = chime.list_tags_for_resource(ResourceARN=meeting_arn)["Tags"]
    listed_map = {t["Key"]: t["Value"] for t in listed}
    assert listed_map.get("sim2real-keep") == "1", (
        f"expected sim2real-keep=1 to survive untag, got {listed_map!r}"
    )
    assert "sim2real-drop" not in listed_map, (
        f"expected sim2real-drop removed by UntagResource, still present in {listed_map!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
