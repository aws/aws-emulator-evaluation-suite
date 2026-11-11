"""stop-meeting-transcription-not-active-is-noop."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-meeting-transcription-not-active-is-noop"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-meetings"]


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises, so a
    target that accepts input AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected TranscriptionConfiguration missing both engine settings to be "
        f"rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopMeetingTranscription on a meeting with no transcription started returns 200, twice;
    Start then Stop on it also succeeds, and Start with an empty TranscriptionConfiguration fails
    with BadRequestException and the exact "Exactly one out of ..." engine-settings message."""
    chime = ctx.client("chime-sdk-meetings")
    # MediaRegion is the media-session region, unrelated to ctx.region/the API endpoint;
    # us-east-1 is a valid, always-available media region.
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    resp1 = chime.stop_meeting_transcription(MeetingId=meeting_id)
    assert resp1["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected idempotent no-op stop, got {resp1['ResponseMetadata']['HTTPStatusCode']}"
    )

    # Effect absent: no hidden "started" state was created by the no-op stop -- stopping
    # again still succeeds the exact same way (still not active).
    resp2 = chime.stop_meeting_transcription(MeetingId=meeting_id)
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the repeated no-op stop to still succeed, "
        f"got {resp2['ResponseMetadata']['HTTPStatusCode']}"
    )

    # Positive control: a real start followed by stop succeeds.
    chime.start_meeting_transcription(
        MeetingId=meeting_id,
        TranscriptionConfiguration={"EngineTranscribeSettings": {"LanguageCode": "en-US"}},
    )
    stop_resp = chime.stop_meeting_transcription(MeetingId=meeting_id)
    assert stop_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected stop-after-start to succeed, "
        f"got {stop_resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    # Genuine overly-permissive boundary: StartMeetingTranscription with a
    # TranscriptionConfiguration that has NEITHER EngineTranscribeSettings NOR
    # EngineTranscribeMedicalSettings is semantically invalid and must be rejected.
    bad_code, bad_message = _client_error(
        lambda: chime.start_meeting_transcription(
            MeetingId=meeting_id,
            TranscriptionConfiguration={},
        )
    )
    assert bad_code == "BadRequestException", (
        f"expected TranscriptionConfiguration missing both engine settings to be "
        f"rejected with BadRequestException, got {bad_code}"
    )
    want_message = (
        "Exactly one out of EngineTranscribeSettings and EngineTranscribeMedicalSettings "
        "must be specified in the TranscriptionConfiguration"
    )
    assert bad_message == want_message, f"expected message {want_message!r}, got {bad_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
