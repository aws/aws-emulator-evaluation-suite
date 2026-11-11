"""create-meeting-idempotent-token-returns-same-meeting."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-meeting-idempotent-token-returns-same-meeting"
GROUP = "idempotency"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-invoking CreateMeeting with the same ClientRequestToken and identical params
    returns the same MeetingId instead of creating a second meeting."""
    chime = ctx.client("chime-sdk-meetings")
    external_meeting_id = ctx.unique_name("sim2real-ext-")
    token = ctx.unique_name("sim2real-token-")

    first = chime.create_meeting(
        ClientRequestToken=token,
        MediaRegion="us-east-1",
        ExternalMeetingId=external_meeting_id,
    )["Meeting"]
    meeting_id = first["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    second = chime.create_meeting(
        ClientRequestToken=token,
        MediaRegion="us-east-1",
        ExternalMeetingId=external_meeting_id,
    )["Meeting"]

    assert second["MeetingId"] == meeting_id, (
        f"repeated CreateMeeting with the same token must dedupe to the original meeting, "
        f"got {second['MeetingId']!r} instead of {meeting_id!r}"
    )
    assert second["ExternalMeetingId"] == external_meeting_id, (
        f"expected ExternalMeetingId {external_meeting_id!r}, got {second['ExternalMeetingId']!r}"
    )

    # Independent read at the destination, through a different operation than the one that
    # mutated: confirms the dedup actually landed server-side and isn't just an echoed response.
    fetched = chime.get_meeting(MeetingId=meeting_id)["Meeting"]
    assert fetched["MeetingId"] == meeting_id, (
        f"GetMeeting must resolve the deduped id, got {fetched['MeetingId']!r}"
    )
    assert fetched["ExternalMeetingId"] == external_meeting_id, (
        f"GetMeeting must reflect the original ExternalMeetingId, got {fetched['ExternalMeetingId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
