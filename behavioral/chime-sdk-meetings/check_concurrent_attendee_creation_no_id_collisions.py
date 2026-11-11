"""concurrent-attendee-creation-no-id-collisions."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-attendee-creation-no-id-collisions"
GROUP = "concurrency"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Firing N CreateAttendee calls concurrently against the same meeting never issues a
    duplicate AttendeeId, and every attendee ends up visible in ListAttendees."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        # MediaRegion is the meeting's media-plane region, independent of the control-plane
        # endpoint region the check runs against; pinned to a supported value.
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    n = 8
    external_ids = [ctx.unique_name(f"sim2real-conc-{i}-") for i in range(n)]

    def _create(eid: str):
        return chime.create_attendee(MeetingId=meeting_id, ExternalUserId=eid)["Attendee"]

    results = []
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_create, eid) for eid in external_ids]
        for fut in as_completed(futures):
            results.append(fut.result())

    assert len(results) == n, f"expected {n} concurrent CreateAttendee calls to complete, got {len(results)}"
    attendee_ids = {r["AttendeeId"] for r in results}
    assert len(attendee_ids) == n, (
        f"expected {n} distinct AttendeeIds, got {len(attendee_ids)} — collision under concurrent creation"
    )
    got_external_ids = {r["ExternalUserId"] for r in results}
    assert got_external_ids == set(external_ids), (
        f"expected create responses to echo {set(external_ids)}, got {got_external_ids}"
    )

    listed = chime.list_attendees(MeetingId=meeting_id)["Attendees"]
    listed_external_ids = {a["ExternalUserId"] for a in listed}
    assert listed_external_ids == set(external_ids), (
        f"expected ListAttendees to show {set(external_ids)}, got {listed_external_ids}"
    )
    listed_attendee_ids = {a["AttendeeId"] for a in listed}
    assert listed_attendee_ids == attendee_ids, (
        f"expected ListAttendees' AttendeeIds ({len(listed_attendee_ids)} distinct) to match the "
        f"{len(attendee_ids)} distinct ids returned by CreateAttendee — a mismatch means the "
        "independent read does not agree with the mutating calls' own responses"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
