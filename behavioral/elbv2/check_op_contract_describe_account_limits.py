"""op-contract-describe-account-limits."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "op-contract-describe-account-limits"
GROUP = "error-semantics"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAccountLimits returns well-formed quota entries; an out-of-range PageSize is
    rejected by the service itself, and the documented boundary value (1) still succeeds."""
    elbv2 = ctx.client("elbv2")

    resp = elbv2.describe_account_limits()
    limits = resp["Limits"]
    assert len(limits) > 0, "expected at least one account limit"
    names = set()
    for lim in limits:
        assert "Name" in lim and "Max" in lim, f"malformed limit entry: {lim}"
        int(lim["Max"])  # Max must be a numeric string
        names.add(lim["Name"])
    assert "application-load-balancers" in names, f"expected a standard limit name, got {names}"

    # PageSize is documented with a valid range of 1-400; 0 is out of range. botocore's own
    # shape constraint (min:1) would short-circuit this locally before the request ever
    # reaches the wire, so use a client with validation disabled to exercise the service's
    # own rejection rather than the SDK's.
    unvalidated = ctx.client("elbv2", config=Config(parameter_validation=False))
    code, message = _error(lambda: unvalidated.describe_account_limits(PageSize=0))
    assert code == "ValidationError", f"unexpected error code {code!r}"
    expected = (
        "1 validation error detected: Value '0' at 'pageSize' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the documented minimum boundary (1) is accepted, not rejected.
    resp_ok = unvalidated.describe_account_limits(PageSize=1)
    assert len(resp_ok["Limits"]) > 0, "PageSize=1 should return at least one limit"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("describe_account_limits(PageSize=0) should have been rejected")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
