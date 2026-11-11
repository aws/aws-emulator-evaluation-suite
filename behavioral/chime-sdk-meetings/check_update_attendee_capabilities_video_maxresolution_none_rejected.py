"""update-attendee-capabilities-video-maxresolution-none-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-attendee-capabilities-video-maxresolution-none-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so a
    target that accepts input AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected UpdateAttendeeCapabilities to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """In a meeting with Video MaxResolution None, an Audio-only UpdateAttendeeCapabilities persists,
    while setting Video to SendReceive fails with BadRequestException and the exact MaxResolution
    message and leaves the attendee's capabilities unchanged."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media routing target, independent of ctx.region -- any valid value is fine
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
        MeetingFeatures={"Video": {"MaxResolution": "None"}, "Content": {"MaxResolution": "None"}},
        Tags=[{"Key": "sim2real-stage", "Value": "audit"}],
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    attendee_id = chime.create_attendee(
        MeetingId=meeting_id,
        ExternalUserId=ctx.unique_name("sim2real-user-"),
        Capabilities={"Audio": "SendReceive", "Video": "None", "Content": "None"},
    )["Attendee"]["AttendeeId"]

    # Positive control: an unrelated Audio-only change (feature-compatible) succeeds first.
    chime.update_attendee_capabilities(
        MeetingId=meeting_id,
        AttendeeId=attendee_id,
        Capabilities={"Audio": "Receive", "Video": "None", "Content": "None"},
    )
    after_control = chime.get_attendee(MeetingId=meeting_id, AttendeeId=attendee_id)["Attendee"]
    assert after_control["Capabilities"] == {"Audio": "Receive", "Video": "None", "Content": "None"}, (
        f"positive control: expected Audio-only capability update to persist, got "
        f"{after_control['Capabilities']!r}"
    )

    # Break exactly one thing: try to turn Video on when the meeting feature forbids it.
    code, message = _client_error(
        lambda: chime.update_attendee_capabilities(
            MeetingId=meeting_id,
            AttendeeId=attendee_id,
            Capabilities={"Audio": "Receive", "Video": "SendReceive", "Content": "None"},
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException when enabling Video capability against a "
        f"MaxResolution=None meeting feature, got error code {code!r}"
    )
    want_message = (
        "Attendee's video capability must be None if MeetingFeatures is configured with "
        "Video:MaxResolution:None"
    )
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"

    # Effect absent: capabilities remain exactly what the positive control left them at.
    final = chime.get_attendee(MeetingId=meeting_id, AttendeeId=attendee_id)["Attendee"]
    assert final["Capabilities"] == {"Audio": "Receive", "Video": "None", "Content": "None"}, (
        f"expected rejected UpdateAttendeeCapabilities to leave capabilities unchanged, got "
        f"{final['Capabilities']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
