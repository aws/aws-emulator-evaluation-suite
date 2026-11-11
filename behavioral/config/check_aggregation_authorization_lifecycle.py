"""aggregation-authorization-lifecycle."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _delete_quiet(cfg, account_id, region):
    try:
        cfg.delete_aggregation_authorization(
            AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchAggregationAuthorizationException":
            raise

CHECK = "aggregation-authorization-lifecycle"
GROUP = 'aggregator'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "identity:standalone", "phase:standalone", "plane:control", "resource:account-singleton:config-aggregation-authorization")
def run(ctx) -> None:
    """PutAggregationAuthorization rejects a non-12-digit AuthorizedAccountId with ValidationException;
    a valid authorization for the caller's own account is listed by DescribeAggregationAuthorizations
    and removed by DeleteAggregationAuthorization."""
    cfg = ctx.client("config")
    region = ctx.region
    account_id = ctx.account
    deleted = []

    def _matching():
        return [
            a
            for a in cfg.describe_aggregation_authorizations()["AggregationAuthorizations"]
            if a["AuthorizedAccountId"] == account_id and a["AuthorizedAwsRegion"] == region
        ]

    if _matching():
        raise RuntimeError(
            "precondition: an aggregation authorization for the caller's own account in this "
            "region already exists; this check creates and deletes its own"
        )

    # Real AWS enforces the account-id pattern as a model constraint and
    # answers with ValidationException (not InvalidParameterValueException).
    # The id is exactly 12 characters so only the pattern constraint fails: two
    # failing constraints come back in no stable order.
    code, message = _error(
        lambda: cfg.put_aggregation_authorization(
            AuthorizedAccountId="not-an-acct1", AuthorizedAwsRegion=region
        )
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value 'not-an-acct1' at 'authorizedAccountId' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: \\d{12}"
    ), message

    cfg.put_aggregation_authorization(
        AuthorizedAccountId=account_id,
        AuthorizedAwsRegion=region,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: deleted or _delete_quiet(cfg, account_id, region))

    found = _matching()
    assert len(found) == 1, f"expected the new authorization listed once, got {len(found)}"

    cfg.delete_aggregation_authorization(
        AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
    )
    deleted.append(True)
    remaining = _matching()
    assert not remaining, f"expected no authorization after delete, got {len(remaining)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
