"""list-service-quotas-invalid-pagination-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-service-quotas-invalid-pagination-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["service-quotas"]

_SERVICE_CODE = "vpc"
# Well-formed (matches the base64-charset NextToken pattern) but not a token AWS
# ever issued, so it cannot resolve to any real continuation position.
_BOGUS_TOKEN = "QUJDREVGRw=="


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a token real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this bogus NextToken, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A syntactically well-formed but unrecognized NextToken is rejected with
    InvalidPaginationTokenException, while the un-paginated call still succeeds
    (positive control)."""
    sq = ctx.client("service-quotas")

    control = sq.list_service_quotas(ServiceCode=_SERVICE_CODE, MaxResults=5)
    assert control["Quotas"], "expected the positive control listing to return quotas"

    code, message = _error_code(
        lambda: sq.list_service_quotas(
            ServiceCode=_SERVICE_CODE, NextToken=_BOGUS_TOKEN, MaxResults=5
        )
    )
    assert code == "InvalidPaginationTokenException", (
        f"expected InvalidPaginationTokenException for a bogus NextToken, got {code!r}"
    )
    expected = (
        "You specified an invalid value for nextToken. "
        "You must get the value from the response to the previous API call."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    control_again = sq.list_service_quotas(ServiceCode=_SERVICE_CODE, MaxResults=5)
    assert control_again["Quotas"], "control listing stopped working after the bad token call"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
