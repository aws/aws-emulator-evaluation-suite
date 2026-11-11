"""query-filter-legacy-not-null-with-value-list-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-legacy-not-null-with-value-list-rejected"
GROUP = "query"
SERVICES = ["dynamodb"]

_ROWS = (
    {"sk": "s0"},
    {"sk": "s1", "memo": "a"},
    {"sk": "s2", "memo": "b"},
)

_WITH_MEMO = tuple(sorted(r["sk"] for r in _ROWS if "memo" in r))


def _ids(resp: dict) -> tuple:
    return tuple(sorted(i["sk"]["S"] for i in resp["Items"]))


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) fn() raises. Raises when the call succeeds instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


_ERR = ("ValidationException",
        "One or more parameter values were invalid: "
        "Invalid number of argument(s) for the NOT_NULL ComparisonOperator")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's legacy QueryFilter NOT_NULL supplied with an AttributeValueList is refused with
    ValidationException; a well-formed NOT_NULL filter still answers over the same partition."""
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for row in _ROWS:
        item = {"pk": {"S": "p1"}, "sk": {"S": row["sk"]}}
        if "memo" in row:
            item["memo"] = {"S": row["memo"]}
        ddb.put_item(TableName=t, Item=item)

    # Positive control: the well-formed NOT_NULL filter answers correctly.
    good = ddb.query(
        TableName=t,
        KeyConditions={"pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"}},
        QueryFilter={"memo": {"ComparisonOperator": "NOT_NULL"}}, ConsistentRead=True,
    )
    assert _ids(good) == _WITH_MEMO, (
        f"the control NOT_NULL query returned {_ids(good)!r}, expected {_WITH_MEMO!r}"
    )

    # Break exactly one thing: NOT_NULL takes zero operands.
    code, msg = _error(lambda: ddb.query(
        TableName=t,
        KeyConditions={"pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"}},
        QueryFilter={"memo": {"ComparisonOperator": "NOT_NULL", "AttributeValueList": [{"S": "x"}]}},
        ConsistentRead=True,
    ))
    assert (code, msg) == _ERR, f"expected {_ERR!r}, got {(code, msg)!r}"

    # A rejected query changes nothing: the control still answers exactly as before.
    again = ddb.query(
        TableName=t,
        KeyConditions={"pk": {"AttributeValueList": [{"S": "p1"}], "ComparisonOperator": "EQ"}},
        QueryFilter={"memo": {"ComparisonOperator": "NOT_NULL"}}, ConsistentRead=True,
    )
    assert _ids(again) == _WITH_MEMO and again["ScannedCount"] == len(_ROWS), (
        f"after the rejection the control query returned {_ids(again)!r} over "
        f"{again['ScannedCount']!r} scanned, expected {_WITH_MEMO!r} over {len(_ROWS)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
