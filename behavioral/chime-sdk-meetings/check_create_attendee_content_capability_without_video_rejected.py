"""create-attendee-content-capability-without-video-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-attendee-content-capability-without-video-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAttendee rejects Content=Receive when Video is only Send (not receiving)
    with BadRequestException, no attendee is created, and requesting the same Content
    capability with Video=SendReceive on the same meeting succeeds (positive control)."""
    chime = ctx.client("chime-sdk-meetings")
    # MediaRegion is the media-session region, unrelated to ctx.region/the API endpoint;
    # any supported value is fine, so it is pinned rather than parameterized.
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    code, message = _client_error(
        lambda: chime.create_attendee(
            MeetingId=meeting_id,
            ExternalUserId=ctx.unique_name("sim2real-bad-"),
            Capabilities={"Audio": "SendReceive", "Video": "Send", "Content": "Receive"},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    want_message = (
        "Attendee's video capability must be set to either SendReceive or Receive when "
        "setting content capability to SendReceive or Receive."
    )
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"

    listed = chime.list_attendees(MeetingId=meeting_id)["Attendees"]
    assert listed == [], "no attendee should have been created for the rejected request"

    # Positive control: Content=Receive is fine once Video is also (Send)Receive.
    good_id = ctx.unique_name("sim2real-good-")
    created = chime.create_attendee(
        MeetingId=meeting_id,
        ExternalUserId=good_id,
        Capabilities={"Audio": "SendReceive", "Video": "SendReceive", "Content": "Receive"},
    )["Attendee"]
    want_capabilities = {"Audio": "SendReceive", "Video": "SendReceive", "Content": "Receive"}
    assert created["Capabilities"] == want_capabilities, (
        f"expected {want_capabilities}, got {created['Capabilities']!r}"
    )

    listed_after = chime.list_attendees(MeetingId=meeting_id)["Attendees"]
    assert len(listed_after) == 1, f"expected exactly 1 attendee, got {len(listed_after)}"
    assert listed_after[0]["ExternalUserId"] == good_id, (
        f"expected {good_id!r}, got {listed_after[0]['ExternalUserId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
