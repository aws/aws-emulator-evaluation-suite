"""batch-update-attendee-capabilities-except-excludes-correctly."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-update-attendee-capabilities-except-excludes-correctly"
GROUP = "data-plane"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchUpdateAttendeeCapabilitiesExcept sets Audio to None on every attendee but the excluded
    one: both included attendees converge to the new set within 30 s, and the excluded attendee
    reads the default capabilities on every poll and at the end."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",  # media-plane routing param, independent of ctx.region
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    default_caps = {"Audio": "SendReceive", "Video": "SendReceive", "Content": "SendReceive"}
    a = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-a-"))["Attendee"]
    b = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-b-"))["Attendee"]
    c = chime.create_attendee(MeetingId=meeting_id, ExternalUserId=ctx.unique_name("sim2real-c-"))["Attendee"]
    assert a["Capabilities"] == default_caps, f"expected default caps {default_caps!r}, got {a['Capabilities']!r}"
    assert c["Capabilities"] == default_caps, f"expected default caps {default_caps!r}, got {c['Capabilities']!r}"

    # Only change Audio -- keep Video/Content at their default valid combination to avoid
    # tripping unrelated content/video interdependency validation rules.
    new_caps = {"Audio": "None", "Video": "SendReceive", "Content": "SendReceive"}
    chime.batch_update_attendee_capabilities_except(
        MeetingId=meeting_id,
        ExcludedAttendeeIds=[{"AttendeeId": c["AttendeeId"]}],
        Capabilities=new_caps,
    )

    deadline = time.time() + 30
    interval = 2
    last_a = last_b = last_c = None
    converged = False
    while time.time() < deadline:
        last_a = chime.get_attendee(MeetingId=meeting_id, AttendeeId=a["AttendeeId"])["Attendee"]["Capabilities"]
        last_b = chime.get_attendee(MeetingId=meeting_id, AttendeeId=b["AttendeeId"])["Attendee"]["Capabilities"]
        last_c = chime.get_attendee(MeetingId=meeting_id, AttendeeId=c["AttendeeId"])["Attendee"]["Capabilities"]
        assert last_c == default_caps, f"excluded attendee's capabilities changed mid-propagation, got {last_c!r}"
        if last_a == new_caps and last_b == new_caps:
            converged = True
            break
        time.sleep(interval)

    assert converged, (
        f"included attendees did not converge to {new_caps!r} within 30s: a={last_a!r} b={last_b!r}"
    )
    assert last_a == new_caps, f"expected {new_caps!r}, got {last_a!r}"
    assert last_b == new_caps, f"expected {new_caps!r}, got {last_b!r}"
    assert last_c == default_caps, f"excluded attendee's capabilities must not change, got {last_c!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
