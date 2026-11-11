"""delete-meeting-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-meeting-not-found-rejected"
GROUP = "overly-permissive"
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
    """DeleteMeeting on a never-created MeetingId succeeds, and GetMeeting on it fails with
    NotFoundException "Meeting <id> not found"; DeleteMeeting on a real meeting ends it, so
    GetMeeting and CreateAttendee then fail with NotFoundException "The meeting has ended"."""
    chime = ctx.client("chime-sdk-meetings")
    bogus_meeting_id = str(uuid.uuid4())

    delete_resp = chime.delete_meeting(MeetingId=bogus_meeting_id)
    assert delete_resp["ResponseMetadata"]["HTTPStatusCode"] in (200, 204), (
        f"expected DeleteMeeting on a never-created MeetingId to be an idempotent no-op, "
        f"got {delete_resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    # Effect absent: nothing was ever created for this ID, and it stays that way.
    get_code, get_message = _client_error(lambda: chime.get_meeting(MeetingId=bogus_meeting_id))
    assert get_code == "NotFoundException", f"got code={get_code!r}"
    want_message = f"Meeting <{bogus_meeting_id}> not found"
    assert get_message == want_message, f"expected message {want_message!r}, got {get_message!r}"

    # Positive control: DeleteMeeting on a real meeting actually deletes it.
    # MediaRegion is the media-session region, unrelated to ctx.region/the API endpoint;
    # any supported value is fine, so it is pinned rather than parameterized.
    real_meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=real_meeting_id))

    chime.delete_meeting(MeetingId=real_meeting_id)
    get_code, get_message = _client_error(lambda: chime.get_meeting(MeetingId=real_meeting_id))
    assert get_code == "NotFoundException", f"expected deleted meeting to read back NotFound, got code={get_code!r}"
    assert get_message == "The meeting has ended", f"got message={get_message!r}"

    # The identifier is dead, not just unreadable: a mutation against it also fails.
    attendee_code, attendee_message = _client_error(
        lambda: chime.create_attendee(MeetingId=real_meeting_id, ExternalUserId=ctx.unique_name("sim2real-post-"))
    )
    assert attendee_code == "NotFoundException", f"expected mutation on deleted meeting to fail, got code={attendee_code!r}"
    assert attendee_message == "The meeting has ended", f"got message={attendee_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
