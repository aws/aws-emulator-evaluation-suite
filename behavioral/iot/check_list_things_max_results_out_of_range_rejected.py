"""list-things-max-results-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-things-max-results-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]

_MAX_RESULTS_OUT_OF_RANGE = (
    "InvalidRequestException",
    "1 validation error detected: Value '251' at 'maxResults' failed to satisfy constraint: "
    "Member must have value less than or equal to 250",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _eventually(fn, predicate, timeout_s: int = 60, interval_s: float = 2.0):
    """Poll ``fn`` until ``predicate`` holds, tolerating transient exceptions.

    Real AWS IoT indexes registry writes asynchronously, so an early read can
    miss a thing that was just created.
    """
    deadline = time.time() + timeout_s
    last_exc = None
    last_val = None
    while time.time() < deadline:
        try:
            last_val = fn()
            if predicate(last_val):
                return last_val
            last_exc = None
        except Exception as exc:  # noqa: BLE001 - transient propagation
            last_exc = exc
        time.sleep(interval_s)
    if last_exc is not None:
        raise AssertionError(f"condition never became true; last error: {last_exc!r}")
    raise AssertionError(f"condition never became true; last value: {last_val!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListThings rejects a maxResults above the documented 250 ceiling with its exact
    validation message, and the boundary value 250 still returns the run's own filtered thing."""
    iot = ctx.client("iot")
    marker = ctx.unique_name("sim2real-behav-thing-maxresults-")
    name = f"{marker}a"
    iot.create_thing(thingName=name, attributePayload={"attributes": {"page-marker": marker}})
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=name))

    def _list(**kw):
        return iot.list_things(attributeName="page-marker", attributeValue=marker, **kw)

    expect_error(lambda: _list(maxResults=251), *_MAX_RESULTS_OUT_OF_RANGE)

    found = _eventually(
        lambda: _list(maxResults=250),
        lambda resp: {t["thingName"] for t in resp.get("things", [])} == {name},
        timeout_s=60,
        interval_s=3,
    )
    assert not found.get("nextToken"), (
        f"a single-thing filtered page at the documented ceiling still carried a nextToken: "
        f"{found.get('nextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
