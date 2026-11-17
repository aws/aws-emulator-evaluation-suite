"""list-things-filtered-full-page-omits-next-token."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-things-filtered-full-page-omits-next-token"
GROUP = "thing-registry-listing"
SERVICES = ["iot"]

_MARKER_ATTR = "sim2real-marker"


def _wait_for_both(iot, marker: str, wanted: set) -> None:
    """Poll filtered ListThings until ``wanted`` is fully indexed; the registry lags on write."""
    deadline = time.monotonic() + 60.0
    latest: set = set()
    while True:
        page = iot.list_things(attributeName=_MARKER_ATTR, attributeValue=marker, maxResults=10)
        latest = {t["thingName"] for t in page.get("things", [])}
        if wanted <= latest:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"registry never indexed both things; last saw {sorted(latest)!r}")
        time.sleep(2.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListThings filtered by attributeName/attributeValue returns every matching thing in one
    page, with no nextToken, when maxResults equals the number of matches."""
    iot = ctx.client("iot")
    marker = ctx.unique_name("sim2real-behav-fullpage-")
    first = ctx.unique_name("sim2real-behav-fullpage-thing-")
    second = ctx.unique_name("sim2real-behav-fullpage-thing-")
    payload = {"attributes": {_MARKER_ATTR: marker}}

    iot.create_thing(thingName=first, attributePayload=payload)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=first))
    iot.create_thing(thingName=second, attributePayload=payload)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=second))

    _wait_for_both(iot, marker, {first, second})

    page = iot.list_things(attributeName=_MARKER_ATTR, attributeValue=marker, maxResults=2)
    things = page.get("things", [])
    assert len(things) == 2, f"expected exactly 2 things on a page sized to the match count, got {things!r}"

    by_name = {t["thingName"]: t for t in things}
    assert set(by_name) == {first, second}, (
        f"the full page held {sorted(by_name)!r}, expected {sorted((first, second))!r}"
    )
    assert not page.get("nextToken"), (
        f"a page sized to the full match count still carried nextToken={page.get('nextToken')!r}"
    )

    for thing_name in (first, second):
        got = by_name[thing_name].get("attributes", {})
        assert got.get(_MARKER_ATTR) == marker, (
            f"{thing_name} reported attributes {got!r}, expected {{{_MARKER_ATTR!r}: {marker!r}}}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
