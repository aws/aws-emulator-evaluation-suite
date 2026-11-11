"""start-and-stop-meeting-transcription-state-transition."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-and-stop-meeting-transcription-state-transition"
GROUP = "transcription"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMeetingTranscription and then StopMeetingTranscription on a live meeting both return
    200, and the same two calls on a nonexistent MeetingId fail with NotFoundException
    "Meeting <id> not found" (the API exposes no transcription state to read back)."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        # MediaRegion is the media/session region, independent of the control-plane
        # endpoint region; any supported media region works.
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
        Tags=[{"Key": "sim2real-stage", "Value": "transcription"}],
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    start_resp = chime.start_meeting_transcription(
        MeetingId=meeting_id,
        TranscriptionConfiguration={"EngineTranscribeSettings": {"LanguageCode": "en-US"}},
    )
    assert start_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected StartMeetingTranscription on a live meeting to succeed, got "
        f"{start_resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    stop_resp = chime.stop_meeting_transcription(MeetingId=meeting_id)
    assert stop_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected StopMeetingTranscription on the now-transcribing meeting to succeed, "
        f"got {stop_resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    bogus_meeting_id = str(uuid.uuid4())
    start_code, start_message = _client_error(
        lambda: chime.start_meeting_transcription(
            MeetingId=bogus_meeting_id,
            TranscriptionConfiguration={"EngineTranscribeSettings": {"LanguageCode": "en-US"}},
        )
    )
    assert start_code == "NotFoundException", (
        f"expected StartMeetingTranscription against a nonexistent MeetingId to be "
        f"rejected with NotFoundException, got {start_code!r}"
    )
    want_message = f"Meeting <{bogus_meeting_id}> not found"
    assert start_message == want_message, f"expected message {want_message!r}, got {start_message!r}"

    stop_code, stop_message = _client_error(
        lambda: chime.stop_meeting_transcription(MeetingId=bogus_meeting_id)
    )
    assert stop_code == "NotFoundException", (
        f"expected StopMeetingTranscription against a nonexistent MeetingId to be "
        f"rejected with NotFoundException, got {stop_code!r}"
    )
    assert stop_message == want_message, f"expected message {want_message!r}, got {stop_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
