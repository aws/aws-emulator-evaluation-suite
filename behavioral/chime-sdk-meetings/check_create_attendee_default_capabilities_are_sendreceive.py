"""create-attendee-default-capabilities-are-sendreceive."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-attendee-default-capabilities-are-sendreceive"
GROUP = "data-plane"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAttendee without an explicit Capabilities argument defaults every attendee
    to SendReceive on Audio, Video, and Content."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # MediaRegion is the media-routing region, an enumerated
        # Chime SDK Meetings parameter independent of the API endpoint/ctx.region.
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    attendee = chime.create_attendee(
        MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-user-")
    )["Attendee"]

    expected = {"Audio": "SendReceive", "Video": "SendReceive", "Content": "SendReceive"}
    assert attendee["Capabilities"] == expected, (
        f"CreateAttendee with no explicit Capabilities: expected {expected}, "
        f"got {attendee['Capabilities']}"
    )

    fetched = chime.get_attendee(MeetingId=meeting_id, AttendeeId=attendee["AttendeeId"])["Attendee"]
    assert fetched["Capabilities"] == expected, (
        f"GetAttendee independent read: expected {expected}, got {fetched['Capabilities']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
