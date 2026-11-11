"""archive-deletion-rejects-further-reads-of-its-completed-search."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "archive-deletion-rejects-further-reads-of-its-completed-search"
GROUP = 'archive-searches'
SERVICES = ['mailmanager']

_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _await_terminal(mm, search_id: str, *, budget_s: float = 120.0, poll_s: float = 2.0) -> str:
    deadline = time.monotonic() + budget_s
    while True:
        state = mm.get_archive_search(SearchId=search_id)["Status"]["State"]
        if state in _TERMINAL:
            return state
        assert time.monotonic() < deadline, f"search did not reach a terminal state within {budget_s}s"
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deleting an archive leaves a search that already completed against it
    unreachable: a later Get names the search gone, a later List names the archive.
    """
    mm = ctx.client("mailmanager")
    arc_id = mm.create_archive(ArchiveName=ctx.unique_name("sim2real-behav-mm-arc-"))["ArchiveId"]
    ctx.on_cleanup(lambda: mm.delete_archive(ArchiveId=arc_id))

    now = datetime.datetime.now(datetime.timezone.utc)
    search_id = mm.start_archive_search(
        ArchiveId=arc_id,
        FromTimestamp=now - datetime.timedelta(days=1),
        ToTimestamp=now,
        MaxResults=10,
    )["SearchId"]

    # Positive control: the search reaches a terminal state and is readable before deletion.
    state = _await_terminal(mm, search_id)
    assert state == "COMPLETED", f"expected COMPLETED on an empty archive, got {state!r}"
    before = mm.get_archive_search(SearchId=search_id)
    assert before["ArchiveId"] == arc_id, f"search recorded archive {before['ArchiveId']!r}"

    mm.delete_archive(ArchiveId=arc_id)

    code, message = _error(lambda: mm.get_archive_search(SearchId=search_id))
    assert code == "ValidationException", f"GetArchiveSearch after archive deletion gave {code!r}"
    assert message == "Search not found.", f"unexpected message {message!r}"

    code, message = _error(lambda: mm.list_archive_searches(ArchiveId=arc_id))
    assert code == "ValidationException", f"ListArchiveSearches after archive deletion gave {code!r}"
    assert message == "Archive is not active.", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
