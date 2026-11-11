"""concurrent-capability-updates-final-state-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-capability-updates-final-state-consistent"
GROUP = "concurrency"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Four concurrent UpdateAttendeeCapabilities calls on one attendee each succeed or fail with
    ConflictException "Request could not be completed due to a conflict.", at least one succeeds,
    and the attendee's final capabilities equal one successful set, never a mix."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    attendee_id = chime.create_attendee(
        MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-user-")
    )["Attendee"]["AttendeeId"]

    candidate_sets = [
        {"Audio": "SendReceive", "Video": "SendReceive", "Content": "SendReceive"},
        {"Audio": "Send", "Video": "Send", "Content": "None"},
        {"Audio": "Receive", "Video": "None", "Content": "None"},
        {"Audio": "None", "Video": "Receive", "Content": "None"},
    ]

    def _update(caps):
        try:
            chime.update_attendee_capabilities(
                MeetingId=meeting_id, AttendeeId=attendee_id, Capabilities=caps
            )
            return ("ok", caps, None)
        except ClientError as err:
            return (err.response["Error"]["Code"], caps, err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=len(candidate_sets)) as pool:
        outcomes = list(pool.map(_update, candidate_sets))

    succeeded = [caps for status, caps, _message in outcomes if status == "ok"]
    for status, _, message in outcomes:
        if status == "ok":
            continue
        # A racer that lost is refused with exactly this conflict.
        assert status == "ConflictException", f"unexpected contention error: {status}"
        assert message == "Request could not be completed due to a conflict.", (
            f"unexpected contention message: {message!r}"
        )
    assert len(succeeded) >= 1, "at least one concurrent updater must win"

    final = chime.get_attendee(MeetingId=meeting_id, AttendeeId=attendee_id)["Attendee"]["Capabilities"]
    assert final in succeeded, f"final capabilities {final} do not match any successful racer's set"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
