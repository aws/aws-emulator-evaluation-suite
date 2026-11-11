"""concurrent-activate-event-source-conflict-detected."""
from __future__ import annotations

import concurrent.futures as cf

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-activate-event-source-conflict-detected"
GROUP = "concurrency"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A non-partner CreatePartnerEventSource is refused and ten concurrent ActivateEventSource
    calls all fail ResourceNotFoundException; if the source exists, a race must hit a conflict."""
    events = ctx.client("events")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    # Positive control: ordinary (non-partner) control-plane operations work with these
    # credentials, so what follows is a targeted partner-privilege guard, not a blanket deny.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    described_bus = events.describe_event_bus(Name=bus_name)
    assert described_bus["Name"] == bus_name, (
        f"expected DescribeEventBus to reflect the created bus {bus_name!r}, got "
        f"{described_bus.get('Name')!r}"
    )

    partner_segment = ctx.unique_name("sim2real-behav-partner-")
    source_name = f"aws.partner/{partner_segment}/testnamespace/testevent"

    try:
        events.create_partner_event_source(Name=source_name, Account=account)
        create_err = None
    except ClientError as err:
        create_err = (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    if create_err is not None:
        namespace = source_name.rsplit("/", 2)[0]
        expected_create = (
            "ValidationException",
            f"Caller is not whitelisted for the event source partner namespace {namespace}",
        )
        assert create_err == expected_create, (
            f"expected the APN-partner-namespace rejection {expected_create}, got {create_err}"
        )

        racer_count = 10
        calls = [
            (lambda: events.activate_event_source(Name=source_name))
            for _ in range(racer_count)
        ]
        errors = _fire_concurrent(calls)
        expected_racer = (
            "ResourceNotFoundException",
            f"Event source {source_name} or event bus {source_name} does not exist.",
        )
        assert all(error == expected_racer for error in errors), (
            "expected every concurrent Activate call against a never-created partner source to "
            f"observe {expected_racer} uniformly, errors={errors}"
        )

        describe_err = _error(lambda: events.describe_event_source(Name=source_name))
        expected_describe = (
            "ResourceNotFoundException",
            f"Event source {source_name} does not exist.",
        )
        assert describe_err == expected_describe, (
            "the concurrent Activate calls must not have fabricated a describable source, got "
            f"{describe_err}"
        )
        return

    ctx.on_cleanup(
        lambda: _ignore_missing(
            lambda: events.delete_partner_event_source(Name=source_name, Account=account)
        )
    )

    racer_count = 10
    calls = [
        (lambda: events.activate_event_source(Name=source_name))
        for _ in range(racer_count)
    ]
    codes = [error[0] for error in _fire_concurrent(calls)]

    assert any(code is None for code in codes), "expected at least one Activate call to succeed"
    assert any(code == "ConcurrentModificationException" for code in codes), (
        f"no ConcurrentModificationException observed among {racer_count} concurrent "
        f"ActivateEventSource calls, codes={codes}"
    )


def _fire_concurrent(fns):
    """(code, message) per call; (None, None) for a call that succeeded."""
    with cf.ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(fn) for fn in fns]
        outcomes = []
        for fut in futures:
            try:
                fut.result()
                outcomes.append((None, None))
            except ClientError as err:
                outcomes.append((err.response["Error"]["Code"], err.response["Error"].get("Message")))
        return outcomes


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_missing(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ValidationException"):
            raise


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
