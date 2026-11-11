"""delete-pending-aggregation-request-malformed-identifiers-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-pending-aggregation-request-malformed-identifiers-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "identity:standalone", "phase:standalone", "plane:control")
def run(ctx) -> None:
    """DeletePendingAggregationRequest rejects a RequesterAccountId failing the 12-digit pattern
    with ValidationException, while a well-formed nonexistent pair is a no-op on the pending list."""
    config = ctx.client("config")
    region = ctx.region

    # RequesterAccountId is modeled with a `\d{12}` pattern and a 12-character length bound.
    # The malformed id is 12 characters long, so it breaks only the pattern and the service
    # reports exactly one validation error (two violations are reported in no fixed order).
    malformed = "not-an-acct1"
    code, message = _error_code(
        lambda: config.delete_pending_aggregation_request(
            RequesterAccountId=malformed, RequesterAwsRegion=region
        )
    )
    assert code == "ValidationException", f"expected a malformed-input rejection, got {code!r}"
    assert message == (
        f"1 validation error detected: Value '{malformed}' at 'requesterAccountId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: \\d{12}"
    ), f"unexpected message: {message!r}"

    # Positive control, proven by an independent read rather than the delete's empty response.
    good_account_id = "111122223333"
    before = _list_all_pending(config)
    assert not _has_request(before, good_account_id, region), (
        f"fixture collision: {good_account_id!r}/{region!r} already pending: {before!r}"
    )

    config.delete_pending_aggregation_request(RequesterAccountId=good_account_id, RequesterAwsRegion=region)

    after = _list_all_pending(config)
    assert after == before, (
        f"a well-formed no-op delete must not perturb the pending list: before={before!r} after={after!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a malformed-input rejection, but the call SUCCEEDED and returned {result!r}")


def _list_all_pending(config) -> list:
    items: list = []
    token = None
    while True:
        kwargs = {"Limit": 20}
        if token:
            kwargs["NextToken"] = token
        page = config.describe_pending_aggregation_requests(**kwargs)
        items.extend(page.get("PendingAggregationRequests", []))
        token = page.get("NextToken")
        if not token:
            break
    return items


def _has_request(requests, account_id: str, region: str) -> bool:
    return any(
        r.get("RequesterAccountId") == account_id and r.get("RequesterAwsRegion") == region
        for r in requests
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
