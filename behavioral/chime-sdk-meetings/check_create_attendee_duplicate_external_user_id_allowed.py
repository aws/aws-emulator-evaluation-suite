"""create-attendee-duplicate-external-user-id-allowed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-attendee-duplicate-external-user-id-allowed"
GROUP = "data-plane"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExternalUserId acts as an idempotency token for CreateAttendee (per AWS docs): two
    CreateAttendee calls with the same ExternalUserId in the same meeting return the SAME
    attendee (same AttendeeId and JoinToken), not two distinct attendees."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media region, independent of the API endpoint region; any supported value works
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    shared_external_id = ctx.unique_name("sim2real-dup-user-")
    a1 = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=shared_external_id)["Attendee"]
    a2 = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=shared_external_id)["Attendee"]

    assert a1["AttendeeId"] == a2["AttendeeId"], f"a1={a1!r} a2={a2!r}"
    assert a1["JoinToken"] == a2["JoinToken"]
    assert a1["ExternalUserId"] == shared_external_id == a2["ExternalUserId"]

    listed = chime.list_attendees(MeetingId=meeting_id)["Attendees"]
    matching = [a for a in listed if a["ExternalUserId"] == shared_external_id]
    assert len(matching) == 1, f"matching={matching!r}"
    assert matching[0]["AttendeeId"] == a1["AttendeeId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
