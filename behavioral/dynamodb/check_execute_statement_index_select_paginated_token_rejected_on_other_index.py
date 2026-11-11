"""execute-statement-index-select-paginated-token-rejected-on-other-index."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-statement-index-select-paginated-token-rejected-on-other-index"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_FOREIGN_TOKEN = ("ValidationException", "NextToken does not match request")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ExecuteStatement to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A paginated PartiQL SELECT against one GSI resumes with its own NextToken, but the same
    token handed to a SELECT against a different GSI on the same table is a ValidationException.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlidxpg-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
            {"AttributeName": "category", "AttributeType": "S"},
            {"AttributeName": "createdAt", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "status-index",
                "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"},
                             {"AttributeName": "createdAt", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "category-index",
                "KeySchema": [{"AttributeName": "category", "KeyType": "HASH"},
                             {"AttributeName": "createdAt", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    deadline = time.monotonic() + 300
    gsi_status = {}
    while time.monotonic() < deadline:
        described = ddb.describe_table(TableName=table)["Table"]
        gsi_status = {i["IndexName"]: i["IndexStatus"] for i in described.get("GlobalSecondaryIndexes", [])}
        if gsi_status.get("status-index") == "ACTIVE" and gsi_status.get("category-index") == "ACTIVE":
            break
        time.sleep(2)
    assert gsi_status.get("status-index") == "ACTIVE" and gsi_status.get("category-index") == "ACTIVE", (
        f"both indexes never became ACTIVE: {gsi_status!r}"
    )

    pk = "P1"
    ddb.put_item(TableName=table, Item={
        "pk": {"S": pk}, "sk": {"S": "s1"}, "status": {"S": "active"},
        "category": {"S": "promo"}, "createdAt": {"S": "2024-01-01"},
    })
    ddb.put_item(TableName=table, Item={
        "pk": {"S": pk}, "sk": {"S": "s2"}, "status": {"S": "active"},
        "category": {"S": "promo"}, "createdAt": {"S": "2024-01-02"},
    })

    status_statement = f"SELECT * FROM \"{table}\".\"status-index\" WHERE status = 'active'"

    # Both items are eventually consistent writes into the GSI; poll until the first page is
    # stable at 2 rows before pagination is graded, so Limit=1 is tested against a settled index.
    deadline = time.monotonic() + 120
    full = []
    while time.monotonic() < deadline:
        full = ddb.execute_statement(Statement=status_statement).get("Items", [])
        if len(full) == 2:
            break
        time.sleep(1)
    assert [i["sk"]["S"] for i in full] == ["s1", "s2"], (
        f"status-index never settled to both items in order: {full!r}"
    )

    page1 = ddb.execute_statement(Statement=status_statement, Limit=1)
    token = page1.get("NextToken")
    assert token, f"the first page of a 2-item GSI partition under Limit=1 must carry a NextToken, got {page1!r}"
    assert [i["sk"]["S"] for i in page1["Items"]] == ["s1"], f"expected only s1 on page 1, got {page1['Items']!r}"

    # Positive control: the SAME statement, replayed with its own token, resumes to the second item.
    page2 = ddb.execute_statement(Statement=status_statement, Limit=1, NextToken=token)
    assert [i["sk"]["S"] for i in page2.get("Items", [])] == ["s2"], (
        f"resuming the issuing index statement with its own token must return the remaining row, "
        f"got {page2.get('Items')!r}"
    )

    # Break exactly one thing: hand the status-index token to a SELECT against the OTHER index.
    category_statement = f"SELECT * FROM \"{table}\".\"category-index\" WHERE category = 'promo'"
    expect_error(
        lambda: ddb.execute_statement(Statement=category_statement, Limit=1, NextToken=token),
        *_FOREIGN_TOKEN,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
