"""get-meeting-reflects-media-region-and-features."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-meeting-reflects-media-region-and-features"
GROUP = "lifecycle"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A meeting created with explicit MeetingFeatures (Video MaxResolution FHD +
    Attendee MaxCount override) reports those exact values back via GetMeeting."""
    chime = ctx.client("chime-sdk-meetings")
    # MediaRegion is the data-plane region under test here (any media-capable AWS
    # region is a valid value) — unrelated to the control-plane region ctx.client
    # dispatches to, so it is not a candidate for ctx.region.
    created = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
        MeetingFeatures={
            "Video": {"MaxResolution": "FHD"},
            "Attendee": {"MaxCount": 25},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Meeting"]
    meeting_id = created["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    assert created["MeetingFeatures"]["Video"]["MaxResolution"] == "FHD", (
        f"expected CreateMeeting to echo Video.MaxResolution=FHD, got {created['MeetingFeatures']['Video'].get('MaxResolution')!r}"
    )
    assert created["MeetingFeatures"]["Attendee"]["MaxCount"] == 25, (
        f"expected CreateMeeting to echo Attendee.MaxCount=25, got {created['MeetingFeatures']['Attendee'].get('MaxCount')!r}"
    )

    fetched = chime.get_meeting(MeetingId=meeting_id)["Meeting"]
    assert fetched["MediaRegion"] == "us-east-1", (
        f"expected GetMeeting MediaRegion=us-east-1, got {fetched.get('MediaRegion')!r}"
    )
    assert fetched["MeetingFeatures"]["Video"]["MaxResolution"] == "FHD", (
        f"expected GetMeeting to reflect Video.MaxResolution=FHD, got {fetched['MeetingFeatures']['Video'].get('MaxResolution')!r}"
    )
    assert fetched["MeetingFeatures"]["Attendee"]["MaxCount"] == 25, (
        f"expected GetMeeting to reflect Attendee.MaxCount=25, got {fetched['MeetingFeatures']['Attendee'].get('MaxCount')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
