"""list-archives-filters-by-prefix-and-source."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-archives-filters-by-prefix-and-source"
GROUP = 'archive'
SERVICES = ['events']

_COMBINED_FILTER_REFUSAL = (
    "At most one filter is allowed for ListArchives. Use either : State, EventSourceArn, or "
    "NamePrefix."
)


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of a ClientError. An unexpected
    SUCCESS raises, because a target ACCEPTING a call real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    """Poll probe() until predicate(result); raise AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting; last={last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListArchives honors NamePrefix and EventSourceArn filters and only
    reports the archive that actually exists."""
    ev = ctx.client("events")
    archive_name = ctx.unique_name("sim2real-behav-evb-archive-")
    default_bus_arn = ev.describe_event_bus(Name="default")["Arn"]
    ev.create_archive(ArchiveName=archive_name, EventSourceArn=default_bus_arn)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ev.delete_archive(ArchiveName=archive_name)))

    _poll_until(
        lambda: ev.describe_archive(ArchiveName=archive_name),
        lambda d: d["State"] in ("ENABLED", "CREATE_FAILED"),
        timeout_s=60,
        interval_s=1.0,
    )

    by_prefix = ev.list_archives(NamePrefix=archive_name)["Archives"]
    assert {a["ArchiveName"] for a in by_prefix} == {archive_name}, (
        f"NamePrefix filter broken: {by_prefix}"
    )

    # ListArchives accepts at most ONE filter (State | EventSourceArn | NamePrefix);
    # combining them must be rejected rather than silently AND-ed.
    combined_err = _error(
        lambda: ev.list_archives(
            NamePrefix=archive_name, EventSourceArn=default_bus_arn
        )
    )
    assert combined_err == ("ValidationException", _COMBINED_FILTER_REFUSAL), (
        f"expected ValidationException for multi-filter ListArchives, got {combined_err!r}"
    )

    by_source = ev.list_archives(EventSourceArn=default_bus_arn)["Archives"]
    assert archive_name in {a["ArchiveName"] for a in by_source}, (
        f"EventSourceArn filter must find the archive: {by_source}"
    )

    none = ev.list_archives(NamePrefix=archive_name + "-nope")["Archives"]
    assert none == [], f"expected no archives for unmatched prefix, got {none}"

    # Deletes prove gone and unusable: an independent read reports the specific
    # not-found code, and a further mutation on the dead id is rejected too.
    ev.delete_archive(ArchiveName=archive_name)
    not_found = ("ResourceNotFoundException", f"Archive {archive_name} does not exist.")
    describe_err = _error(lambda: ev.describe_archive(ArchiveName=archive_name))
    assert describe_err == not_found, (
        f"expected a deleted archive to be gone with {not_found!r}, got {describe_err!r}"
    )
    redelete_err = _error(lambda: ev.delete_archive(ArchiveName=archive_name))
    assert redelete_err == not_found, (
        f"expected a second delete of a gone archive to be rejected with {not_found!r}, "
        f"got {redelete_err!r}"
    )
    gone_from_prefix = ev.list_archives(NamePrefix=archive_name)["Archives"]
    assert gone_from_prefix == [], (
        f"deleted archive must not still be reported by NamePrefix, got {gone_from_prefix}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
