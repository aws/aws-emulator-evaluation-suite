"""batch-create-attendee-creates-all-and-returns-join-tokens."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-create-attendee-creates-all-and-returns-join-tokens"
GROUP = "data-plane"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchCreateAttendee provisions every requested attendee in one call, each with a
    distinct AttendeeId/JoinToken, individually retrievable via GetAttendee."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media region, independent of the API endpoint region; any supported value works
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    external_ids = [ctx.unique_name(f"sim2real-batch-{i}-") for i in range(5)]
    resp = chime.batch_create_attendee(
        MeetingId=meeting_id,
        Attendees=[{"ExternalUserId": eid} for eid in external_ids],
    )

    assert resp.get("Errors", []) == [], f"expected no per-attendee errors, got {resp.get('Errors')!r}"
    attendees = resp["Attendees"]
    assert len(attendees) == 5, f"expected 5 attendees created, got {len(attendees)}"
    got_external_ids = {a["ExternalUserId"] for a in attendees}
    assert got_external_ids == set(external_ids), (
        f"expected ExternalUserId set {set(external_ids)!r}, got {got_external_ids!r}"
    )
    attendee_ids = {a["AttendeeId"] for a in attendees}
    assert len(attendee_ids) == 5, f"expected 5 distinct AttendeeIds, got {len(attendee_ids)} unique of 5"
    join_tokens = {a["JoinToken"] for a in attendees}
    assert len(join_tokens) == 5, f"expected 5 distinct JoinTokens, got {len(join_tokens)} unique of 5"

    for attendee in attendees:
        fetched = chime.get_attendee(MeetingId=meeting_id, AttendeeId=attendee["AttendeeId"])["Attendee"]
        assert fetched["ExternalUserId"] == attendee["ExternalUserId"], (
            f"GetAttendee (independent read) ExternalUserId mismatch for {attendee['AttendeeId']}: "
            f"expected {attendee['ExternalUserId']!r}, got {fetched['ExternalUserId']!r}"
        )
        assert fetched["JoinToken"] == attendee["JoinToken"], (
            f"GetAttendee (independent read) JoinToken mismatch for {attendee['AttendeeId']}: "
            f"expected {attendee['JoinToken']!r}, got {fetched['JoinToken']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
