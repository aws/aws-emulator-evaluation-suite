"""list-attendees-pagination-completeness."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-attendees-pagination-completeness"
GROUP = "data-plane"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAttendees paginated with a small MaxResults, followed via NextToken, surfaces
    every attendee exactly once."""
    chime = ctx.client("chime-sdk-meetings")
    meeting_id = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    expected_external_ids = set()
    for i in range(8):
        eid = ctx.unique_name(f"sim2real-page-{i}-")
        chime.create_attendee(MeetingId=meeting_id, ExternalUserId=eid)
        expected_external_ids.add(eid)

    collected = []
    next_token = None
    pages = 0
    page_sizes = []
    while True:
        kwargs = {"MeetingId": meeting_id, "MaxResults": 3}
        if next_token:
            kwargs["NextToken"] = next_token
        page = chime.list_attendees(**kwargs)
        collected.extend(page["Attendees"])
        page_sizes.append(len(page["Attendees"]))
        pages += 1
        next_token = page.get("NextToken")
        if not next_token or pages > 20:
            break

    # 8 attendees at MaxResults=3 cannot be satisfied by a single page; a target that
    # ignores MaxResults and dumps everything at once would still pass the completeness
    # checks below, so pagination itself must be asserted, not just its end result.
    assert pages > 1, f"expected multiple pages for 8 attendees at MaxResults=3, got {pages}"
    assert all(size <= 3 for size in page_sizes), f"page exceeded MaxResults=3: {page_sizes}"

    collected_external_ids = [a["ExternalUserId"] for a in collected]
    assert len(collected_external_ids) == len(set(collected_external_ids)), "duplicate attendee across pages"
    assert set(collected_external_ids) == expected_external_ids, (
        f"expected {expected_external_ids!r}, got {set(collected_external_ids)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
