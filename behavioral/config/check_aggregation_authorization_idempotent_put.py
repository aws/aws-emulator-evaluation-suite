"""aggregation-authorization-idempotent-put."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aggregation-authorization-idempotent-put"
GROUP = 'aggregator'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:representation", "identity:standalone", "phase:standalone", "plane:control", "resource:account-singleton:config-aggregation-authorization")
def run(ctx) -> None:
    """PutAggregationAuthorization is idempotent on the
    (AuthorizedAccountId, AuthorizedAwsRegion) pair: repeating it must not
    create a duplicate authorization. The authorized account is the caller's own."""
    cfg = ctx.client("config")
    account_id = ctx.account
    region = ctx.region
    deleted = []

    def _matching():
        return [
            a
            for a in cfg.describe_aggregation_authorizations()[
                "AggregationAuthorizations"
            ]
            if a["AuthorizedAccountId"] == account_id
            and a["AuthorizedAwsRegion"] == region
        ]

    if _matching():
        raise RuntimeError(
            "precondition: an aggregation authorization for the caller's own account in this "
            "region already exists; this check creates and deletes its own"
        )

    cfg.put_aggregation_authorization(
        AuthorizedAccountId=account_id,
        AuthorizedAwsRegion=region,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: deleted or _delete_quiet(cfg, account_id, region))

    first = _matching()
    assert len(first) == 1, f"expected 1 authorization after the first put, got {len(first)}"
    arn = first[0]["AggregationAuthorizationArn"]

    cfg.put_aggregation_authorization(
        AuthorizedAccountId=account_id,
        AuthorizedAwsRegion=region,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    second = _matching()
    assert len(second) == 1, f"expected 1 authorization after the second put, got {len(second)}"
    assert second[0]["AggregationAuthorizationArn"] == arn, (
        "the repeated put changed AggregationAuthorizationArn"
    )

    cfg.delete_aggregation_authorization(
        AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
    )
    deleted.append(True)
    remaining = _matching()
    assert not remaining, f"expected no authorization after delete, got {len(remaining)}"


def _delete_quiet(cfg, account_id, region):
    try:
        cfg.delete_aggregation_authorization(
            AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchAggregationAuthorizationException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
