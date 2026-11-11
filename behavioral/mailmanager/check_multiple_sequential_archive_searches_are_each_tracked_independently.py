"""multiple-sequential-archive-searches-are-each-tracked-independently."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "multiple-sequential-archive-searches-are-each-tracked-independently"
GROUP = 'archive-searches'
SERVICES = ['mailmanager']

_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
_SEARCH_COUNT = 3


def _await_terminal(mm, search_id: str, *, budget_s: float = 120.0, poll_s: float = 2.0) -> str:
    deadline = time.monotonic() + budget_s
    while True:
        state = mm.get_archive_search(SearchId=search_id)["Status"]["State"]
        if state in _TERMINAL:
            return state
        assert time.monotonic() < deadline, f"search did not reach a terminal state within {budget_s}s"
        time.sleep(poll_s)


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Running several searches over one archive's lifetime each gets a distinct id
    and its own terminal state, and the archive's listing accounts for every one.
    """
    mm = ctx.client("mailmanager")
    arc_id = mm.create_archive(ArchiveName=ctx.unique_name("sim2real-behav-mm-arc-"))["ArchiveId"]
    ctx.on_cleanup(lambda: mm.delete_archive(ArchiveId=arc_id))

    now = datetime.datetime.now(datetime.timezone.utc)
    search_ids = []
    for i in range(_SEARCH_COUNT):
        search_id = mm.start_archive_search(
            ArchiveId=arc_id,
            FromTimestamp=now - datetime.timedelta(days=1 + i),
            ToTimestamp=now,
            MaxResults=10,
        )["SearchId"]
        state = _await_terminal(mm, search_id)
        assert state == "COMPLETED", f"search {i} on an empty archive reached {state!r}"
        search_ids.append(search_id)

    assert len(set(search_ids)) == _SEARCH_COUNT, f"expected distinct ids, got {search_ids!r}"

    for sid in search_ids:
        results = mm.get_archive_search_results(SearchId=sid)["Rows"]
        assert results == [], f"search {sid} on an empty archive returned rows {results!r}"

    listed = {
        s["SearchId"]
        for page in mm.get_paginator("list_archive_searches").paginate(ArchiveId=arc_id)
        for s in page["Searches"]
    }
    assert listed == set(search_ids), f"ListArchiveSearches returned {sorted(listed)}, expected {sorted(search_ids)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
