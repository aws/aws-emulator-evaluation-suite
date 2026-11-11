"""scan-filter-ne-and-not-contains-on-missing-attribute."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-ne-and-not-contains-on-missing-attribute"
GROUP = 'scan'
SERVICES = ['dynamodb']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter NE and NULL match a missing attribute; NOT_NULL and NOT_CONTAINS do not.
    NOT_CONTAINS also diverges from its FilterExpression equivalent, 'NOT contains()', which does.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-scanmiss-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 30})

    ddb.put_item(TableName=table, Item={"id": {"S": "has-attr"}, "attr": {"S": "hello"}})
    ddb.put_item(TableName=table, Item={"id": {"S": "no-attr"}})

    def scan_ids(**kwargs) -> list:
        resp = ddb.scan(TableName=table, ConsistentRead=True, **kwargs)
        return sorted(item["id"]["S"] for item in resp["Items"])

    names = {"#a": "attr"}

    # NE: the attribute's absence is treated as "not equal", so the missing item matches and
    # the item carrying the equal value is excluded -- a positive control that NE is not
    # vacuously true for everything.
    ne = scan_ids(ScanFilter={"attr": {"ComparisonOperator": "NE",
                                       "AttributeValueList": [{"S": "hello"}]}})
    assert ne == ["no-attr"], f"ScanFilter NE on a missing attribute returned {ne!r}, expected only the item without the attribute"

    ne_expr = scan_ids(FilterExpression="#a <> :v", ExpressionAttributeNames=names,
                       ExpressionAttributeValues={":v": {"S": "hello"}})
    assert ne_expr == ne, f"FilterExpression '<>' returned {ne_expr!r}, must match legacy NE's {ne!r}"

    # NOT_CONTAINS: the attribute's absence is treated as no match, the opposite convention
    # from NE -- the missing item is excluded, same as the item whose value does contain the
    # substring.
    not_contains = scan_ids(ScanFilter={"attr": {"ComparisonOperator": "NOT_CONTAINS",
                                                 "AttributeValueList": [{"S": "hel"}]}})
    assert not_contains == [], f"ScanFilter NOT_CONTAINS on a missing attribute returned {not_contains!r}, expected no items"

    # The FilterExpression form built from attribute_exists's own complement -- NOT contains() --
    # is NOT the same function: contains() evaluates false for a missing attribute, so its
    # negation matches it, unlike the legacy operator above.
    not_contains_expr = scan_ids(FilterExpression=f"NOT contains(#a, :v)", ExpressionAttributeNames=names,
                                 ExpressionAttributeValues={":v": {"S": "hel"}})
    assert not_contains_expr == ["no-attr"], (
        f"'NOT contains(#a, :v)' returned {not_contains_expr!r}, expected the missing-attribute "
        f"item -- it diverges from legacy NOT_CONTAINS, which excluded it"
    )

    # NOT_NULL/NULL mean exists/not-exists, matching attribute_exists()/attribute_not_exists().
    not_null = scan_ids(ScanFilter={"attr": {"ComparisonOperator": "NOT_NULL"}})
    null_ = scan_ids(ScanFilter={"attr": {"ComparisonOperator": "NULL"}})
    assert not_null == ["has-attr"], f"ScanFilter NOT_NULL returned {not_null!r}, expected only the item carrying the attribute"
    assert null_ == ["no-attr"], f"ScanFilter NULL returned {null_!r}, expected only the item missing the attribute"

    have = scan_ids(FilterExpression="attribute_exists(#a)", ExpressionAttributeNames=names)
    lack = scan_ids(FilterExpression="attribute_not_exists(#a)", ExpressionAttributeNames=names)
    assert have == not_null, f"attribute_exists() returned {have!r}, must match ScanFilter NOT_NULL's {not_null!r}"
    assert lack == null_, f"attribute_not_exists() returned {lack!r}, must match ScanFilter NULL's {null_!r}"

    # NULL and NOT_NULL are the two legacy operators documented to take no AttributeValueList;
    # supplying one is rejected, not silently ignored.
    code, message = _error(lambda: ddb.scan(
        TableName=table,
        ScanFilter={"attr": {"ComparisonOperator": "NULL", "AttributeValueList": [{"S": "x"}]}},
    ))
    assert code == "ValidationException", f"expected ValidationException supplying a value to NULL, got {code}: {message!r}"
    assert message == (
        "One or more parameter values were invalid: Invalid number of argument(s) for the NULL "
        "ComparisonOperator"
    ), f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
