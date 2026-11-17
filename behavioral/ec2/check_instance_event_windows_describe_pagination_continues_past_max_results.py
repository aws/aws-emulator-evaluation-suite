"""instance-event-windows-describe-pagination-continues-past-max-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "instance-event-windows-describe-pagination-continues-past-max-results"
GROUP = "pagination"
SERVICES = ["ec2"]

_PAGE_SIZE = 20
_COUNT = _PAGE_SIZE + 1


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceEventWindows with MaxResults below the matching set size pages through
    NextToken: no page exceeds MaxResults, no window repeats across pages, and the pages
    together return exactly the matching windows."""
    ec2 = ctx.client("ec2")
    marker = ctx.unique_name("sim2real-behav-iewpg-")

    window_ids = set()
    for _ in range(_COUNT):
        window_id = ec2.create_instance_event_window(
            TimeRanges=[{"StartWeekDay": "sunday", "StartHour": 2, "EndWeekDay": "sunday", "EndHour": 6}],
            TagSpecifications=[
                {"ResourceType": "instance-event-window", "Tags": [{"Key": "sim2real-marker", "Value": marker}]}
            ],
        )["InstanceEventWindow"]["InstanceEventWindowId"]
        ctx.on_cleanup(_delete_window(ec2, window_id))
        window_ids.add(window_id)

    filters = [{"Name": "tag:sim2real-marker", "Values": [marker]}]

    # Filters may apply after the MaxResults slice, so a page can be short; follow NextToken to the end.
    pages, token = [], None
    while True:
        kwargs = {"Filters": filters, "MaxResults": _PAGE_SIZE, **({"NextToken": token} if token else {})}
        page = ec2.describe_instance_event_windows(**kwargs)
        ids = [w["InstanceEventWindowId"] for w in page["InstanceEventWindows"]]
        assert len(ids) <= _PAGE_SIZE, f"a page held {len(ids)} windows, more than MaxResults={_PAGE_SIZE}"
        pages.append(ids)
        token = page.get("NextToken")
        if not token:
            break
        assert len(pages) <= _COUNT + 1, f"NextToken did not end after {len(pages)} pages"

    assert len(pages) >= 2, (
        f"{_COUNT} matching windows with MaxResults={_PAGE_SIZE} must page at least once, got {pages!r}"
    )
    returned = [i for ids in pages for i in ids]
    assert len(returned) == len(set(returned)), f"a window appeared on more than one page: {pages!r}"
    assert set(returned) == window_ids, (
        f"the pages together returned {sorted(set(returned))}, expected exactly the {len(window_ids)} "
        f"windows this check created: {sorted(window_ids)}"
    )

def _delete_window(ec2, window_id: str):
    def run_delete() -> None:
        ec2.delete_instance_event_window(InstanceEventWindowId=window_id, ForceDelete=True)

    return run_delete


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
