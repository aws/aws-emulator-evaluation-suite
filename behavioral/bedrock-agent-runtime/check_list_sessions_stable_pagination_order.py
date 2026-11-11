"""list-sessions-stable-pagination-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-sessions-stable-pagination-order"
GROUP = "ordering"
SERVICES = ["bedrock-agent-runtime"]

_WALK_ATTEMPTS = 3


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two paginated ListSessions walks with a small page size each list the check's five sessions
    exactly once, in the same relative order."""
    client = ctx.client("bedrock-agent-runtime")

    created_ids = []
    for _ in range(5):
        session_id = client.create_session(tags={"env": "sim2real"})["sessionId"]
        created_ids.append(session_id)

        def _end_and_delete(sid=session_id) -> None:
            client.end_session(sessionIdentifier=sid)
            client.delete_session(sessionIdentifier=sid)

        ctx.on_cleanup(_end_and_delete)

    created_set = set(created_ids)

    # Sessions other callers create or delete during a walk can shift its pages, so a pair of walks
    # in which one misses or repeats one of the check's sessions is read again, a bounded number of
    # times; the last pair is graded.
    for _ in range(_WALK_ATTEMPTS):
        walk_1 = _list_all_sessions_paginated(client, page_size=2)
        walk_2 = _list_all_sessions_paginated(client, page_size=2)
        if all(walk.count(sid) == 1 for walk in (walk_1, walk_2) for sid in created_ids):
            break

    # No duplicates and no gaps within a single walk.
    counts_1 = {}
    for sid in walk_1:
        counts_1[sid] = counts_1.get(sid, 0) + 1
    for sid in created_ids:
        assert counts_1.get(sid, 0) == 1, (
            f"session {sid} appeared {counts_1.get(sid, 0)} times in a single "
            "ListSessions pagination walk (expected exactly 1)"
        )

    # Filter each independent walk down to just our known sessions, preserving
    # the order encountered, and require the two walks agree.
    ours_in_walk_1 = [sid for sid in walk_1 if sid in created_set]
    ours_in_walk_2 = [sid for sid in walk_2 if sid in created_set]
    assert len(ours_in_walk_1) == 5, f"walk 1 only saw {len(ours_in_walk_1)}/5 of our sessions"
    assert ours_in_walk_1 == ours_in_walk_2, (
        "ListSessions pagination order was not stable across two immediate "
        f"walks: {ours_in_walk_1} != {ours_in_walk_2}"
    )


def _list_all_sessions_paginated(client, page_size: int) -> list[str]:
    session_ids: list[str] = []
    next_token = None
    for _ in range(500):  # bounded traversal, not a time-based wait
        kwargs = {"maxResults": page_size}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_sessions(**kwargs)
        session_ids.extend(s["sessionId"] for s in resp.get("sessionSummaries", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    else:
        raise AssertionError("ListSessions pagination did not terminate within 500 pages")
    return session_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
