"""invalid-pagination-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invalid-pagination-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListServiceQuotas with a well-formed NextToken the server never issued is refused with
    InvalidPaginationTokenException and its exact message, while the same call without a token
    succeeds before and after."""
    sq = ctx.client("service-quotas")
    bogus_token = "A" * 40 + "=="

    before = sq.list_service_quotas(ServiceCode="ec2")["Quotas"]
    assert before, "expected ListServiceQuotas without a token to succeed before the bad-token call"

    code, message = _error_code(
        lambda: sq.list_service_quotas(ServiceCode="ec2", NextToken=bogus_token)
    )
    assert code == "InvalidPaginationTokenException", (
        f"expected InvalidPaginationTokenException, got {code!r}"
    )
    expected = (
        "You specified an invalid value for nextToken. "
        "You must get the value from the response to the previous API call."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = sq.list_service_quotas(ServiceCode="ec2")["Quotas"]
    assert after, "expected ListServiceQuotas without a token to still succeed after the bad-token call"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
