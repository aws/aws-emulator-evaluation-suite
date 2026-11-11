"""create-attendee-reserved-external-user-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-attendee-reserved-external-user-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a reserved 'aws:' ExternalUserId, but CreateAttendee SUCCEEDED "
        f"and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAttendee rejects an ExternalUserId beginning with the reserved 'aws:' prefix
    with BadRequestException, no attendee is created for it, and a normal ExternalUserId
    on the same meeting still succeeds (positive control)."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media-plane routing param, independent of ctx.region
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    code, message = _client_error(
        lambda: chime.create_attendee(MeetingId=meeting_id, ExternalUserId="aws:reserved-user")
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    want_message = "Validation error for ExternalUserId, prefix 'aws:' is reserved."
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"

    listed = chime.list_attendees(MeetingId=meeting_id)["Attendees"]
    assert listed == [], "no attendee should have been created for the rejected request"

    # Positive control: a normal ExternalUserId on the same meeting succeeds.
    valid_id = ctx.unique_name("sim2real-user-")
    created = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=valid_id)["Attendee"]
    assert created["ExternalUserId"] == valid_id, (
        f"expected ExternalUserId {valid_id!r}, got {created['ExternalUserId']!r}"
    )

    listed_after = chime.list_attendees(MeetingId=meeting_id)["Attendees"]
    assert len(listed_after) == 1, f"expected exactly 1 attendee, got {len(listed_after)}"
    assert listed_after[0]["ExternalUserId"] == valid_id, (
        f"expected ExternalUserId {valid_id!r}, got {listed_after[0]['ExternalUserId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
