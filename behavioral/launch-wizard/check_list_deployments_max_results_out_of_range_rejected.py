"""list-deployments-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-deployments-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["launch-wizard"]


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDeployments enforces the modeled maxResults range (1-100): a value of 101 is
    rejected with ValidationException, while 100 (the upper bound) is accepted."""
    lw = ctx.client("launch-wizard")

    code, message = _client_error(lambda: lw.list_deployments(maxResults=101))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    ), f"got message={message!r}"

    # positive control: the boundary value itself is accepted
    resp = lw.list_deployments(maxResults=100)
    assert isinstance(resp.get("deployments"), list), (
        f"maxResults=100 (the modeled upper bound) must be accepted and return a "
        f"deployments list, got {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
