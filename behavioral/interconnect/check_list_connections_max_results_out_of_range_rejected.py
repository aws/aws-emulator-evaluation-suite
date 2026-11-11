"""list-connections-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "list-connections-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnections rejects maxResults values outside the documented 1-100 range, but accepts values inside it."""
    ic = ctx.client("interconnect")

    # Above the ceiling: botocore's client-side validator only enforces the modeled
    # Minimum for this shape, not the Maximum, so this request reaches the wire and
    # it is AWS's own rejection being asserted here.
    too_high_code, too_high_message = _error(lambda: ic.list_connections(maxResults=101))
    assert too_high_code == "ValidationException", f"got {too_high_code!r}"
    assert too_high_message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), f"got {too_high_message!r}"

    # Below the minimum: botocore DOES enforce the modeled Minimum client-side, so a
    # normally-validated call never reaches the network. Disable client-side parameter
    # validation to observe the service's own boundary enforcement instead of botocore's.
    unvalidated = ctx.client("interconnect", config=Config(parameter_validation=False))
    too_low_code, too_low_message = _error(lambda: unvalidated.list_connections(maxResults=0))
    assert too_low_code == "ValidationException", f"got {too_low_code!r}"
    assert too_low_message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    ), f"got {too_low_message!r}"

    # positive control: an in-range maxResults value is accepted
    resp = ic.list_connections(maxResults=5)
    assert "connections" in resp, f"in-range maxResults=5 unexpectedly rejected: {resp!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
