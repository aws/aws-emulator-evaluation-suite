"""describe-contributor-insights-resource-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-contributor-insights-resource-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeContributorInsights on a nonexistent table raises ResourceNotFoundException with the exact message,
    while on a table the check created it answers with status DISABLED.
    """
    ddb = ctx.client("dynamodb")

    table_name = ctx.unique_name("sim2real-behav-ci-notfound-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ctx, table_name)

    control = ddb.describe_contributor_insights(TableName=table_name)
    assert control["ContributorInsightsStatus"] == "DISABLED", (
        f"expected positive control to succeed with DISABLED, got {control}"
    )

    fake_table = ctx.unique_name("sim2real-notable-")
    code, message = _error(lambda: ddb.describe_contributor_insights(TableName=fake_table))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Requested resource not found: Table: {fake_table} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_table_active(ctx, table_name, timeout_s=180, interval_s=3):
    import time

    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_table(TableName=table_name)["Table"]["TableStatus"]
        if last == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {table_name} never reached ACTIVE, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
