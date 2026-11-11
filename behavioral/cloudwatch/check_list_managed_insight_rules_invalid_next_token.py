"""list-managed-insight-rules-invalid-next-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-managed-insight-rules-invalid-next-token"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListManagedInsightRules with a malformed NextToken raises InvalidNextToken "INVALID_TOKEN:
    Unsupported token version.", while the same call without a token returns a ManagedRules list."""
    ddb = ctx.client("dynamodb")
    cw = ctx.client("cloudwatch")

    table_name = ctx.unique_name("sim2real-mir-table-")
    table_arn = ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-check", "Value": "list-managed-insight-rules-invalid-next-token"}],
    )["TableDescription"]["TableArn"]

    def _delete_table():
        # DeleteTable refuses a table that is still CREATING, so wait for ACTIVE first.
        ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
        ddb.delete_table(TableName=table_name)

    ctx.on_cleanup(_delete_table)

    ok = cw.list_managed_insight_rules(ResourceARN=table_arn)
    assert "ManagedRules" in ok, f"expected a well-formed ManagedRules response, got {ok!r}"

    code, message = _error(
        lambda: cw.list_managed_insight_rules(
            ResourceARN=table_arn,
            NextToken="sim2real-not-a-real-pagination-token",
        )
    )
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code}"
    assert message == 'INVALID_TOKEN: Unsupported token version.', f"unexpected InvalidNextToken message: {message!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
