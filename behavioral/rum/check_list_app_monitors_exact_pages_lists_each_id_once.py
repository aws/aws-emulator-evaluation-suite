"""list-app-monitors-exact-pages-lists-each-id-once."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags

CHECK = "list-app-monitors-exact-pages-lists-each-id-once"
GROUP = "listing"
SERVICES = ["rum"]

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def _unique_monitor():
    return f"sim2real-behav-{uuid.uuid4().hex[:10]}"


def _create_app_monitor(ctx, r, *, domain, platform=None):
    """CreateAppMonitor with a unique name (registered for teardown). Returns (name, id)."""
    name = _unique_monitor()
    kwargs = {"Name": name, "Tags": {"sim2real:managed": "true"}}
    if platform is not None:
        kwargs["Platform"] = platform
    else:
        kwargs["Domain"] = domain
    resp = r.create_app_monitor(**kwargs)
    ctx.on_cleanup(lambda: r.delete_app_monitor(Name=name))
    return name, resp["Id"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """3 app monitors each get a distinct lowercase-UUID Id that GetAppMonitor confirms; walking
    ListAppMonitors(MaxResults=1) yields exactly one summary on every page carrying a NextToken,
    every created id exactly once with its Name/State/Platform, and no NextToken on the last page.
    """
    r = ctx.client("rum")

    name_a, id_a = _create_app_monitor(ctx, r, domain=None, platform="Android")
    name_b, id_b = _create_app_monitor(ctx, r, domain="first.example.com")
    name_c, id_c = _create_app_monitor(ctx, r, domain="second.example.com")

    created = {
        id_a: (name_a, "Android"),
        id_b: (name_b, "Web"),
        id_c: (name_c, "Web"),
    }

    for mon_id in created:
        assert isinstance(mon_id, str) and _UUID_RE.match(mon_id), (
            f"Id is not a lowercase 8-4-4-4-12 hex UUID: {mon_id!r}"
        )
    assert len({id_a, id_b, id_c}) == 3, f"CreateAppMonitor returned a duplicate id: {created}"

    for mon_id, (name, _platform) in created.items():
        stored_id = r.get_app_monitor(Name=name)["AppMonitor"]["Id"]
        assert stored_id == mon_id, (
            f"GetAppMonitor({name!r}) returned {stored_id!r}, expected {mon_id!r}"
        )

    seen_by_id = {}
    pages = 0
    last_token = None
    while True:
        kwargs = {"MaxResults": 1}
        if last_token:
            kwargs["NextToken"] = last_token
        page = r.list_app_monitors(**kwargs)
        summaries = page.get("AppMonitorSummaries", [])
        next_token = page.get("NextToken")
        pages += 1

        assert len(summaries) <= 1, (
            f"page {pages} returned {len(summaries)} summaries with MaxResults=1: {summaries}"
        )
        if next_token:
            assert len(summaries) == 1, (
                f"page {pages} carries a NextToken but returned {len(summaries)} summaries, "
                f"expected exactly 1"
            )

        for summary in summaries:
            mon_id = summary["Id"]
            if mon_id in created:
                assert mon_id not in seen_by_id, (
                    f"page {pages}: id {mon_id!r} was already listed on an earlier page"
                )
                seen_by_id[mon_id] = summary

        if next_token is None:
            break
        last_token = next_token
        assert pages < 500, "exceeded 500 pages walking ListAppMonitors(MaxResults=1)"

    assert set(seen_by_id) == set(created), (
        f"walked all pages but saw {sorted(seen_by_id)}, expected {sorted(created)}"
    )

    for mon_id, (name, platform) in created.items():
        summary = seen_by_id[mon_id]
        assert summary["Name"] == name, (
            f"summary for {mon_id!r} has Name {summary['Name']!r}, expected {name!r}"
        )
        assert summary["State"] == "CREATED", (
            f"summary for {mon_id!r} has State {summary['State']!r}, expected 'CREATED'"
        )
        assert summary["Platform"] == platform, (
            f"summary for {mon_id!r} has Platform {summary['Platform']!r}, expected {platform!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
