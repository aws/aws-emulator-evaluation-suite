"""describe-contributor-insights-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-contributor-insights-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeContributorInsights on a table name that does not exist raises
    ResourceNotFoundException; the same call against a real table succeeds and reports
    contributor insights as disabled by default."""
    ddb = ctx.client("dynamodb")
    missing_table = ctx.unique_name("sim2real-behav-nope-")

    code, message = _error(lambda: ddb.describe_contributor_insights(TableName=missing_table))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Requested resource not found: Table: {missing_table} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_status(ctx, table_name, "ACTIVE")

    desc = ddb.describe_contributor_insights(TableName=table_name)
    status = desc["ContributorInsightsStatus"]
    assert status == "DISABLED", f"expected DISABLED, got {status}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_table_status(ctx, table_name, target_status, timeout_s=180, interval_s=3):
    import time

    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table_name)["Table"]
        last = desc["TableStatus"]
        if last == target_status:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never reached {target_status}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
