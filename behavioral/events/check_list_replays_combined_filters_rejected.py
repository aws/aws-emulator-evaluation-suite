"""list-replays-combined-filters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-replays-combined-filters-rejected"
GROUP = 'replay'
SERVICES = ['events']


_COMBINED_FILTER_REFUSAL = (
    "ValidationException",
    "At most one filter is allowed for ListReplays. Use either : State, EventSourceArn, or "
    "NamePrefix.",
)


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListReplays accepts one of NamePrefix, State or EventSourceArn: each alone succeeds,
    but every pairing is rejected with ValidationException, though the model declares no
    such constraint."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real:managed", "Value": "true"}])["EventBusArn"]
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))

    archive_name = ctx.unique_name("sim2real-behav-archive-")
    archive_arn = ev.create_archive(ArchiveName=archive_name, EventSourceArn=bus_arn)["ArchiveArn"]
    ctx.on_cleanup(lambda a=archive_name: ev.delete_archive(ArchiveName=a))

    prefix = ctx.unique_name("sim2real-behav-replay-")

    # Positive controls: each filter alone succeeds.
    ev.list_replays(NamePrefix=prefix)
    ev.list_replays(State="COMPLETED")
    ev.list_replays(EventSourceArn=archive_arn)

    # Negative: every pairing of two filters together is rejected, not just one combination.
    err = _error(lambda: ev.list_replays(NamePrefix=prefix, State="COMPLETED"))
    assert err == _COMBINED_FILTER_REFUSAL, (
        f"NamePrefix+State together: expected {_COMBINED_FILTER_REFUSAL!r}, got {err!r}"
    )
    err = _error(lambda: ev.list_replays(NamePrefix=prefix, EventSourceArn=archive_arn))
    assert err == _COMBINED_FILTER_REFUSAL, (
        f"NamePrefix+EventSourceArn together: expected {_COMBINED_FILTER_REFUSAL!r}, got {err!r}"
    )
    err = _error(lambda: ev.list_replays(State="COMPLETED", EventSourceArn=archive_arn))
    assert err == _COMBINED_FILTER_REFUSAL, (
        f"State+EventSourceArn together: expected {_COMBINED_FILTER_REFUSAL!r}, got {err!r}"
    )

    # Positive control, repeated after every rejection: a single filter still works, so the
    # rejections above are a validation rule, not an archive/bus the account merely lacks.
    resp = ev.list_replays(NamePrefix=prefix)
    assert resp["Replays"] == [], f"expected no replays under a fresh unique prefix, got {resp['Replays']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
