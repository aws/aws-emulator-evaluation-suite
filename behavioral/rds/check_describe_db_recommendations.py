"""describe-db-recommendations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-db-recommendations"
GROUP = 'maintenance'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBRecommendations: the account-wide recommendations catalog is always describable
    (possibly empty) both unfiltered and filtered by a valid status. Overly-permissive boundary: an
    unrecognized Filters Name must be rejected rather than silently ignored.
    """
    rds = ctx.client("rds")
    resp = rds.describe_db_recommendations()
    assert "DBRecommendations" in resp, f"missing DBRecommendations key: {resp!r}"
    assert isinstance(resp["DBRecommendations"], list), (
        f"expected a list, got {type(resp['DBRecommendations'])!r}"
    )

    resp2 = rds.describe_db_recommendations(Filters=[{"Name": "status", "Values": ["active"]}])
    assert isinstance(resp2.get("DBRecommendations"), list), (
        f"expected a list for status filter, got {resp2.get('DBRecommendations')!r}"
    )

    err = _rejection(
        lambda: rds.describe_db_recommendations(
            Filters=[{"Name": "sim2real-bogus-filter-name", "Values": ["x"]}]
        )
    )
    assert err.get("Code") == "InvalidParameterValue", f"unexpected error: {err}"
    assert err.get("Message") == (
        "1 validation error detected: Value 'sim2real-bogus-filter-name' at "
        "'filters.1.member.name' failed to satisfy constraint: Member must satisfy regular "
        "expression pattern: [a-z-]+"
    ), f"unexpected InvalidParameterValue message: {err}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
