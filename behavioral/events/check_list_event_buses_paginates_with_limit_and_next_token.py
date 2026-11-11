"""list-event-buses-paginates-with-limit-and-next-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-event-buses-paginates-with-limit-and-next-token"
GROUP = "event-bus"
SERVICES = ["events"]

_BUSES = 3
_MAX_PAGES = 10


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEventBuses with Limit=1 over three buses returns one bus per page and together each bus
    exactly once; Limit above the maximum of 100 and an unissued NextToken are both refused."""
    events = ctx.client("events")
    prefix = ctx.unique_name("sim2real-behav-pg-")
    names = {f"{prefix}-{i}" for i in range(_BUSES)}
    for name in sorted(names):
        events.create_event_bus(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda n=name: events.delete_event_bus(Name=n))

    pages: list[list[str]] = []
    token = None
    while True:
        kwargs = {"NamePrefix": prefix, "Limit": 1}
        if token:
            kwargs["NextToken"] = token
        resp = events.list_event_buses(**kwargs)
        page = [b["Name"] for b in resp.get("EventBuses", [])]
        assert len(page) <= 1, f"Limit=1 returned a page of {len(page)} buses: {page!r}"
        pages.append(page)
        token = resp.get("NextToken")
        if not token:
            break
        assert len(pages) < _MAX_PAGES, (
            f"ListEventBuses kept returning a NextToken after {len(pages)} pages for {_BUSES} buses: "
            f"{pages!r} — the token does not advance"
        )

    listed = [n for page in pages for n in page]
    assert sorted(listed) == sorted(names), (
        f"the pages together must return each of the {_BUSES} buses exactly once; got {listed!r}"
    )
    assert sum(1 for page in pages if page) == _BUSES, (
        f"with Limit=1 the {_BUSES} buses must arrive on {_BUSES} separate pages, got {pages!r}"
    )

    code, message = _error(lambda: events.list_event_buses(NamePrefix=prefix, Limit=101))
    assert (code, message) == (
        "ValidationException",
        "1 validation error detected: Value '101' at 'limit' failed to satisfy constraint: "
        "Member must have value less than or equal to 100",
    ), f"Limit=101 must be refused, got {code!r} {message!r}"

    code, message = _error(lambda: events.list_event_buses(NamePrefix=prefix, NextToken="sim2real-not-a-token"))
    assert (code, message) == ("ValidationException", "Parameter NextToken is not valid."), (
        f"a NextToken the service never issued must be refused, got {code!r} {message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
