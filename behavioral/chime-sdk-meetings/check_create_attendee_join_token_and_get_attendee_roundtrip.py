"""create-attendee-join-token-and-get-attendee-roundtrip."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "create-attendee-join-token-and-get-attendee-roundtrip"
GROUP = "data-plane"
SERVICES = ["chime-sdk-meetings"]

_GUID_RE = re.compile(r"^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAttendee issues a well-formed AttendeeId/JoinToken pair, and GetAttendee
    returns the same attendee data by ID."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    external_user_id = ctx.unique_name("sim2real-user-")
    created = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=external_user_id)["Attendee"]

    assert _GUID_RE.match(created["AttendeeId"]), f"AttendeeId not a well-formed GUID: {created['AttendeeId']!r}"
    assert len(created["JoinToken"]) >= 2, f"JoinToken shorter than modeled min length 2: {created['JoinToken']!r}"
    assert created["ExternalUserId"] == external_user_id, (
        f"expected ExternalUserId {external_user_id!r}, got {created['ExternalUserId']!r}"
    )

    fetched = chime.get_attendee(MeetingId=meeting_id, AttendeeId=created["AttendeeId"])["Attendee"]
    assert fetched["AttendeeId"] == created["AttendeeId"], (
        f"expected AttendeeId {created['AttendeeId']!r}, got {fetched['AttendeeId']!r}"
    )
    assert fetched["ExternalUserId"] == external_user_id, (
        f"expected ExternalUserId {external_user_id!r}, got {fetched['ExternalUserId']!r}"
    )
    assert fetched["JoinToken"] == created["JoinToken"], (
        f"expected JoinToken {created['JoinToken']!r}, got {fetched['JoinToken']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
