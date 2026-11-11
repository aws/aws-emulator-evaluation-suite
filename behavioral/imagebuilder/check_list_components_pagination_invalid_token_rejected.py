"""list-components-pagination-invalid-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-components-pagination-invalid-token-rejected"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListComponents rejects a malformed pagination token with InvalidParameterValueException."""
    ib = ctx.client("imagebuilder")
    code, message = _error(lambda: ib.list_components(nextToken="not-a-real-pagination-token=="))
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected = "The value supplied for parameter 'nextToken' is not valid. The provided token does not meet the required format."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: an unpaginated call succeeds normally
    resp = ib.list_components(owner="Self")
    assert "componentVersionList" in resp, f"expected componentVersionList in response, got keys {sorted(resp)!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
