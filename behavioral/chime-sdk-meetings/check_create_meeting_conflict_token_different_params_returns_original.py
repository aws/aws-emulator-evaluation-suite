"""create-meeting-conflict-token-different-params-returns-original."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-meeting-conflict-token-different-params-returns-original"
GROUP = "state-machine"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMeeting with a reused ClientRequestToken returns the original meeting, with identical
    parameters and with a different ExternalMeetingId alike; the different ExternalMeetingId is
    ignored, so the response and GetMeeting keep the original one."""
    chime = ctx.client("chime-sdk-meetings")
    token = ctx.unique_name("sim2real-token-")
    original_ext_id = ctx.unique_name("sim2real-ext-orig-")

    original = chime.create_meeting(
        ClientRequestToken=token,
        MediaRegion="us-east-1",  # media-plane region pin, independent of ctx.region; any supported value is fine for this check
        ExternalMeetingId=original_ext_id,
    )["Meeting"]
    meeting_id = original["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    # Positive control: same token + identical params is idempotent, not a conflict.
    same_params = chime.create_meeting(
        ClientRequestToken=token,
        MediaRegion="us-east-1",
        ExternalMeetingId=original_ext_id,
    )["Meeting"]
    assert same_params["MeetingId"] == meeting_id, (
        f"expected idempotent replay to return the original meeting {meeting_id!r}, "
        f"got {same_params['MeetingId']!r}"
    )

    # Reuse the token with a different ExternalMeetingId: no exception (a ClientError here
    # fails the check), and the response reflects the token-keyed dedup -- the ORIGINAL
    # meeting, not a new one, and the differing field is silently ignored (not applied).
    different_ext_id = ctx.unique_name("sim2real-ext-conflict-")
    second = chime.create_meeting(
        ClientRequestToken=token,
        MediaRegion="us-east-1",
        ExternalMeetingId=different_ext_id,
    )["Meeting"]
    assert second["MeetingId"] == meeting_id, "token dedup must return the original meeting, not a new one"
    assert second["ExternalMeetingId"] == original_ext_id, (
        f"differing ExternalMeetingId on token reuse must not overwrite the original, "
        f"got {second['ExternalMeetingId']!r}"
    )

    # Effect absent: the original meeting's ExternalMeetingId was never overwritten.
    fetched = chime.get_meeting(MeetingId=meeting_id)["Meeting"]
    assert fetched["ExternalMeetingId"] == original_ext_id, (
        f"expected the original ExternalMeetingId {original_ext_id!r} to survive the token-keyed "
        f"dedup untouched, got {fetched['ExternalMeetingId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
