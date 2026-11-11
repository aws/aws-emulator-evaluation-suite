"""legacy-expected-comparator-type-mismatch-on-put."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "legacy-expected-comparator-type-mismatch-on-put"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")

# A stored attribute compared with a legacy ComparisonOperator condition whose
# AttributeValueList element is a different type never matches for every comparator
# except NE, which treats the type mismatch itself as inequality.
_NEVER_MATCHES = ("EQ", "LE", "LT", "GE", "GT")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the conditional PutItem to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A legacy Expected ComparisonOperator condition whose value type differs from the stored
    attribute's never matches, so PutItem fails with ConditionalCheckFailedException, for every
    comparator except NE, where the type mismatch itself satisfies "not equal".

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/LegacyConditionalParameters.Conditions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbtm-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 1, "MaxAttempts": 60})

    def _stored(pk):
        return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")

    def _try_conditional_put(pk, condition):
        ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "num": {"N": "6"}})
        ddb.put_item(
            TableName=table,
            Item={"pk": {"S": pk}, "num": {"N": "6"}, "marker": {"S": "applied"}},
            Expected={"num": condition},
        )

    # S "6" compared against a stored N "6": EQ, LE, LT, GE, GT and BETWEEN all reject the
    # conditional write, and the pre-existing item is left exactly as it was.
    for op in _NEVER_MATCHES:
        pk = f"s-vs-n-{op.lower()}"
        expect_error(
            lambda op=op, pk=pk: _try_conditional_put(pk, {"ComparisonOperator": op, "AttributeValueList": [{"S": "6"}]}),
            *_CCFE,
        )
        unchanged = _stored(pk)
        assert unchanged == {"pk": {"S": pk}, "num": {"N": "6"}}, (
            f"{op}: a rejected conditional PutItem changed the stored item: {unchanged!r}"
        )

    pk = "s-vs-n-between"
    expect_error(
        lambda: _try_conditional_put(pk, {"ComparisonOperator": "BETWEEN", "AttributeValueList": [{"S": "0"}, {"S": "9"}]}),
        *_CCFE,
    )
    unchanged = _stored(pk)
    assert unchanged == {"pk": {"S": pk}, "num": {"N": "6"}}, (
        f"BETWEEN: a rejected conditional PutItem changed the stored item: {unchanged!r}"
    )

    # NE on the same type mismatch: AWS treats the attribute as "not equal" to a value of a
    # different type, so the condition is satisfied and the write lands.
    pk = "s-vs-n-ne"
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "num": {"N": "6"}})
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": pk}, "num": {"N": "6"}, "marker": {"S": "applied"}},
        Expected={"num": {"ComparisonOperator": "NE", "AttributeValueList": [{"S": "6"}]}},
    )
    landed = _stored(pk)
    assert landed == {"pk": {"S": pk}, "num": {"N": "6"}, "marker": {"S": "applied"}}, (
        f"NE: a satisfied conditional PutItem did not land: {landed!r}"
    )

    # A number compared against a number SET of the same member is the same rule: EQ never
    # matches a set-typed value, NE does.
    pk = "n-vs-ns-eq"
    expect_error(
        lambda: _try_conditional_put(pk, {"ComparisonOperator": "EQ", "AttributeValueList": [{"NS": ["6"]}]}),
        *_CCFE,
    )
    unchanged = _stored(pk)
    assert unchanged == {"pk": {"S": pk}, "num": {"N": "6"}}, (
        f"EQ N-vs-NS: a rejected conditional PutItem changed the stored item: {unchanged!r}"
    )

    pk = "n-vs-ns-ne"
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "num": {"N": "6"}})
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": pk}, "num": {"N": "6"}, "marker": {"S": "applied"}},
        Expected={"num": {"ComparisonOperator": "NE", "AttributeValueList": [{"NS": ["6"]}]}},
    )
    landed = _stored(pk)
    assert landed == {"pk": {"S": pk}, "num": {"N": "6"}, "marker": {"S": "applied"}}, (
        f"NE N-vs-NS: a satisfied conditional PutItem did not land: {landed!r}"
    )

    # Positive control: the comparator mechanism itself works -- a matched type condition
    # (EQ against the same N value) succeeds, so the rejections above are not vacuous.
    pk = "matched-type-eq"
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "num": {"N": "6"}})
    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": pk}, "num": {"N": "6"}, "marker": {"S": "applied"}},
        Expected={"num": {"ComparisonOperator": "EQ", "AttributeValueList": [{"N": "6"}]}},
    )
    landed = _stored(pk)
    assert landed == {"pk": {"S": pk}, "num": {"N": "6"}, "marker": {"S": "applied"}}, (
        f"positive control: a matched-type EQ condition did not let the write land: {landed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
