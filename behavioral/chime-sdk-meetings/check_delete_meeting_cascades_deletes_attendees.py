"""delete-meeting-cascades-deletes-attendees."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-meeting-cascades-deletes-attendees"
GROUP = "lifecycle"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Right after DeleteMeeting, GetMeeting, ListAttendees and CreateAttendee on the meeting all
    fail with NotFoundException "The meeting has ended". GetAttendee is not asserted: AWS does
    not bound how long an attendee record outlives its meeting."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media routing target, independent of ctx.region -- any valid value is fine
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    # DeleteMeeting on an already-deleted meeting succeeds, so this is safe after the
    # explicit delete below and covers an early failure before it.
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    chime.create_attendee(MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-a1-"))
    chime.create_attendee(MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-a2-"))

    chime.delete_meeting(MeetingId=meeting_id)

    # The meeting record itself is gone immediately (synchronous).
    mc, mc_message = _client_error(lambda: chime.get_meeting(MeetingId=meeting_id))
    assert mc == "NotFoundException", f"got code={mc!r}"
    assert mc_message == "The meeting has ended", f"got message={mc_message!r}"

    # ListAttendees is scoped by MeetingId (like GetMeeting), so it too must immediately
    # reject once the meeting is gone, rather than returning a stale/empty attendee list.
    lc, lc_message = _client_error(lambda: chime.list_attendees(MeetingId=meeting_id))
    assert lc == "NotFoundException", f"got code={lc!r}"
    assert lc_message == "The meeting has ended", f"got message={lc_message!r}"

    # A mutation on the dead meeting id must also fail, not just a read.
    cc, cc_message = _client_error(
        lambda: chime.create_attendee(MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-a3-"))
    )
    assert cc == "NotFoundException", f"got code={cc!r}"
    assert cc_message == "The meeting has ended", f"got message={cc_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
