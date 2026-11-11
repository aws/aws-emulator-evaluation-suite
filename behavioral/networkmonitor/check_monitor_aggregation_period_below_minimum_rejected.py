"""monitor-aggregation-period-below-minimum-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "monitor-aggregation-period-below-minimum-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMonitor rejects an aggregationPeriod below the modeled minimum of 30
    (schema range min=30) with BadRequestException, no monitor is created, and the
    boundary value 30 itself is accepted (positive control) and persists."""
    nm = ctx.client("networkmonitor")
    bad_name = ctx.unique_name("sim2real-nm-mon-")

    # AggregationPeriod's Minimum(30) range trait means botocore refuses to even SEND
    # aggregationPeriod=10 -- it raises a local ParamValidationError before any request
    # reaches the wire. That tells us nothing about the target: an emulator that ignores the
    # bound entirely would fail identically. Disable client-side parameter validation so the
    # out-of-range value actually goes on the wire and it is the SERVICE's own rejection that
    # gets asserted.
    #
    # NetworkMonitor rejects the out-of-range value with
    # BadRequestException, not the modeled ValidationException -- a range-trait violation is
    # caught by the service's frontend deserializer before request routing ever reaches
    # application code that would raise the modeled shape.
    unvalidated_nm = ctx.client("networkmonitor", config=Config(parameter_validation=False))
    err = _error(lambda: unvalidated_nm.create_monitor(monitorName=bad_name, aggregationPeriod=10))
    assert err["Code"] == "BadRequestException", f"expected BadRequestException, got {err['Code']!r}"
    expected = "Invalid request body"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    listed = _list_all_monitors(nm)
    assert not any(m["monitorName"] == bad_name for m in listed), (
        "monitor must not exist after a rejected create"
    )

    # positive control: the boundary value 30 is accepted
    good_name = ctx.unique_name("sim2real-nm-mon-")
    created = nm.create_monitor(
        monitorName=good_name, aggregationPeriod=30, tags={"sim2real": "true"}
    )
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=good_name))
    assert created["aggregationPeriod"] == 30, (
        f"expected the boundary value 30 to be accepted, CreateMonitor returned "
        f"{created['aggregationPeriod']!r}"
    )

    # Terminal assertion is an independent read (GetMonitor), not the mutating CreateMonitor
    # response, so a target that echoes 30 without persisting it cannot pass.
    fetched = nm.get_monitor(monitorName=good_name)
    assert fetched["aggregationPeriod"] == 30, (
        f"boundary aggregationPeriod=30 did not persist, GetMonitor returned "
        f"{fetched['aggregationPeriod']!r}"
    )


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _list_all_monitors(nm):
    out = []
    token = None
    while True:
        kwargs = {"maxResults": 25}
        if token:
            kwargs["nextToken"] = token
        resp = nm.list_monitors(**kwargs)
        out.extend(resp.get("monitors", []))
        token = resp.get("nextToken")
        if not token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
