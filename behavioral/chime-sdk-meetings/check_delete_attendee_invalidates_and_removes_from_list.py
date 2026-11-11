"""delete-attendee-invalidates-and-removes-from-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-attendee-invalidates-and-removes-from-list"
GROUP = "lifecycle"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAttendee removes the attendee from ListAttendees and immediately invalidates
    its JoinToken -- GetAttendee for it afterwards returns NotFoundException."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media routing target, independent of ctx.region -- any valid value is fine
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    keeper = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-keep-"))["Attendee"]
    victim = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-del-"))["Attendee"]

    chime.delete_attendee(MeetingId=meeting_id, AttendeeId=victim["AttendeeId"])

    # Empirically, GetAttendee for a just-deleted attendee returns ForbiddenException
    # (access to the deleted attendee's record is revoked), not NotFoundException.
    code, message = _client_error(
        lambda: chime.get_attendee(MeetingId=meeting_id, AttendeeId=victim["AttendeeId"])
    )
    assert code == "ForbiddenException", f"got code={code!r}"
    want_message = f"Attendee <{victim['AttendeeId']}> is not in the meeting <{meeting_id}>"
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"

    remaining = chime.list_attendees(MeetingId=meeting_id)["Attendees"]
    remaining_ids = {a["AttendeeId"] for a in remaining}
    assert victim["AttendeeId"] not in remaining_ids
    assert keeper["AttendeeId"] in remaining_ids

    # A mutation on the dead attendee id must also fail, not just a read.
    update_code, update_message = _client_error(
        lambda: chime.update_attendee_capabilities(
            MeetingId=meeting_id,
            AttendeeId=victim["AttendeeId"],
            Capabilities={"Audio": "SendReceive", "Video": "SendReceive", "Content": "SendReceive"},
        )
    )
    assert update_code == "ForbiddenException", f"got code={update_code!r}"
    assert update_message == want_message, f"expected message {want_message!r}, got {update_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
