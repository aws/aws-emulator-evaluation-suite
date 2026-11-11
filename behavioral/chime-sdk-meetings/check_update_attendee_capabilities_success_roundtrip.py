"""update-attendee-capabilities-success-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-attendee-capabilities-success-roundtrip"
GROUP = "data-plane"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAttendeeCapabilities persists a new Audio/Video/Content capability set, and
    the change is visible on the very next GetAttendee."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media-plane region, independent of ctx.region (API endpoint)
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    attendee = chime.create_attendee(
        MeetingId=meeting_id,
        ExternalUserId=ctx.unique_name("sim2real-user-"),
        Capabilities={"Audio": "SendReceive", "Video": "SendReceive", "Content": "SendReceive"},
    )["Attendee"]

    new_caps = {"Audio": "Receive", "Video": "Send", "Content": "None"}
    updated = chime.update_attendee_capabilities(
        MeetingId=meeting_id, AttendeeId=attendee["AttendeeId"], Capabilities=new_caps
    )["Attendee"]
    assert updated["Capabilities"] == new_caps, (
        f"UpdateAttendeeCapabilities response expected {new_caps}, got {updated['Capabilities']!r}"
    )

    fetched = chime.get_attendee(MeetingId=meeting_id, AttendeeId=attendee["AttendeeId"])["Attendee"]
    assert fetched["Capabilities"] == new_caps, (
        f"GetAttendee after update expected {new_caps}, got {fetched['Capabilities']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
