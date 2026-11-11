"""list-protection-groups-invalid-pagination-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-protection-groups-invalid-pagination-token-rejected"
GROUP = "error-semantics"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an unsubscribed account ListProtectionGroups without a token fails with ResourceNotFoundException "The
    subscription does not exist.", while a malformed NextToken gets InvalidPaginationTokenException "Invalid
    pagination token.", so the token is validated first.
    """
    shield = ctx.client("shield")

    baseline_code, baseline_message = _error_code(lambda: shield.list_protection_groups())
    assert baseline_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the untokened baseline, got {baseline_code!r}"
    )
    assert baseline_message == "The subscription does not exist.", f"unexpected message {baseline_message!r}"

    bogus_token = "not-a-real-continuation-token-" + "x" * 40
    code, message = _error_code(lambda: shield.list_protection_groups(NextToken=bogus_token))
    assert code == "InvalidPaginationTokenException", f"expected InvalidPaginationTokenException, got {code!r}"
    assert message == "Invalid pagination token.", f"unexpected message {message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
