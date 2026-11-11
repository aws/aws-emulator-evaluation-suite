"""list-monitors-pagination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-monitors-pagination"
GROUP = "listing"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMonitors with maxResults=1 pages through nextToken, returning at most 1 item per page
    and eventually surfacing every monitor created in this check.
    """
    nm = ctx.client("networkmonitor")
    names = [ctx.unique_name("sim2real-nwm-mon-") for _ in range(3)]
    for n in names:
        nm.create_monitor(monitorName=n, aggregationPeriod=60, tags={"sim2real": "list-monitors-pagination"})
        ctx.on_cleanup(lambda n=n: nm.delete_monitor(monitorName=n))

    seen = []
    next_token = None
    for _ in range(500):
        kwargs = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = nm.list_monitors(**kwargs)
        assert len(page["monitors"]) <= 1, "maxResults=1 must cap each page at 1 item"
        seen.extend(m["monitorName"] for m in page["monitors"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    else:
        raise AssertionError("pagination did not terminate within 500 pages")

    for n in names:
        assert n in seen, f"monitor {n} never surfaced while paginating with maxResults=1"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
