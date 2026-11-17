"""update-item-add-and-delete-through-nested-placeholders-reject-mismatched-leaf-types."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-and-delete-through-nested-placeholders-reject-mismatched-leaf-types"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_TYPE_MISMATCH = (
    "ValidationException",
    "An operand in the update expression has an incorrect data type",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert `fn()` raises a ClientError with exactly `(code, message)`; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err["Code"], err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD and DELETE through a per-segment placeholder path are each refused when the named
    nested leaf is not the type the action requires, and the item stays unchanged.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "orderId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "orderId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"orderId": {"S": "ord-7"}}
    original = {
        **key,
        "label": {"S": "ok"},
        "shipment": {"M": {
            "route": {"M": {
                "hops": {"L": [{"S": "west"}, {"S": "east"}]},
                "carrier": {"S": "freight-co"},
            }},
            "metrics": {"M": {"weight": {"N": "10"}}},
        }},
    }
    ddb.put_item(TableName=table, Item=original)

    hops_names = {"#s": "shipment", "#r": "route", "#h": "hops"}
    carrier_names = {"#s": "shipment", "#r": "route", "#c": "carrier"}
    weight_names = {"#s": "shipment", "#m": "metrics", "#w": "weight"}

    # ADD requires a Number or Set stored attribute; shipment.route.hops is a List.
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #s.#r.#h :five",
        ExpressionAttributeNames=hops_names, ExpressionAttributeValues={":five": {"N": "5"}},
    ), *_TYPE_MISMATCH)
    after_add = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_add == original, (
        f"the refused ADD through shipment.route.hops must leave the item unchanged, got {after_add!r}"
    )

    # DELETE requires a Set stored attribute; shipment.route.carrier is a String.
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE #s.#r.#c :tag",
        ExpressionAttributeNames=carrier_names, ExpressionAttributeValues={":tag": {"SS": ["freight-co"]}},
    ), *_TYPE_MISMATCH)
    after_delete = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_delete == original, (
        f"the refused DELETE through shipment.route.carrier must leave the item unchanged, got {after_delete!r}"
    )

    # Positive control: ADD through the same style of path onto a Number leaf still applies.
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #s.#m.#w :delta",
        ExpressionAttributeNames=weight_names, ExpressionAttributeValues={":delta": {"N": "7"}},
        ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"shipment": {"M": {"metrics": {"M": {"weight": {"N": "17"}}}}}}, (
        f"the positive-control ADD through shipment.metrics.weight returned {resp['Attributes']!r}, "
        f"expected weight=17"
    )

    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    expected_final = {
        **key,
        "label": {"S": "ok"},
        "shipment": {"M": {
            "route": {"M": {
                "hops": {"L": [{"S": "west"}, {"S": "east"}]},
                "carrier": {"S": "freight-co"},
            }},
            "metrics": {"M": {"weight": {"N": "17"}}},
        }},
    }
    assert final == expected_final, (
        f"after the one successful ADD the item is {final!r}, expected exactly {expected_final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
