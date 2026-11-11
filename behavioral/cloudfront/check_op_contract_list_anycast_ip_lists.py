"""op-contract-listAnycastIpLists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listAnycastIpLists"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAnycastIpLists returns a well-shaped collection; an out-of-range MaxItems yields InvalidArgument."""
    cf = ctx.client("cloudfront")

    resp = cf.list_anycast_ip_lists()
    body = resp["AnycastIpLists"]
    assert isinstance(body["Quantity"], int) and body["Quantity"] >= 0, (
        f"expected a non-negative integer Quantity, got {body.get('Quantity')!r}"
    )
    assert isinstance(body["Items"], list), f"expected Items to be a list, got {body['Items']!r}"
    assert len(body["Items"]) <= body["Quantity"], (
        f"Items length {len(body['Items'])} exceeds reported Quantity {body['Quantity']}"
    )

    # Unlike the classic XML-based List* operations, ListAnycastIpLists
    # types MaxItems as an integer, so an out-of-range (non-positive) value
    # -- rather than a non-numeric string, which botocore would reject
    # locally before ever reaching the service -- is what exercises the
    # server-side InvalidArgument boundary.
    code, msg = _error(lambda: cf.list_anycast_ip_lists(MaxItems=-1))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert msg == "MaxItems must be a non-zero positive integer.", f"unexpected InvalidArgument message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
