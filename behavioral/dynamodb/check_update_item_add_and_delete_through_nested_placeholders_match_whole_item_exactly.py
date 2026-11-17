"""update-item-add-and-delete-through-nested-placeholders-match-whole-item-exactly."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-add-and-delete-through-nested-placeholders-match-whole-item-exactly"
GROUP = "expressions"
SERVICES = ["dynamodb"]


def _normalize(value):
    """``value`` with every String/Number/Binary Set member put in a fixed order."""
    if "M" in value:
        return {"M": {k: _normalize(v) for k, v in value["M"].items()}}
    if "L" in value:
        return {"L": [_normalize(v) for v in value["L"]]}
    for set_type in ("SS", "NS", "BS"):
        if set_type in value:
            return {set_type: sorted(value[set_type])}
    return value


def _normalize_item(item):
    return {name: _normalize(value) for name, value in item.items()}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ADD and DELETE through per-segment placeholder paths change only the addressed nested
    leaf; the parent map is left present but empty once its last set member is deleted.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "deviceId", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "deviceId", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"deviceId": {"S": "edge-gw-1"}}
    original = {
        **key,
        "firmware": {"S": "v3"},
        "telemetry": {"M": {
            "uptime": {"M": {"seconds": {"N": "100"}}},
            "alerts": {"M": {"codes": {"SS": ["overheat", "vibration"]}}},
        }},
    }
    ddb.put_item(TableName=table, Item=original)

    uptime_names = {"#t": "telemetry", "#u": "uptime", "#s": "seconds"}
    alerts_names = {"#t": "telemetry", "#a": "alerts", "#c": "codes"}

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #t.#u.#s :delta",
        ExpressionAttributeNames=uptime_names, ExpressionAttributeValues={":delta": {"N": "30"}},
    )
    after_add = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    expected_after_add = {
        **key,
        "firmware": {"S": "v3"},
        "telemetry": {"M": {
            "uptime": {"M": {"seconds": {"N": "130"}}},
            "alerts": {"M": {"codes": {"SS": ["overheat", "vibration"]}}},
        }},
    }
    assert _normalize_item(after_add) == _normalize_item(expected_after_add), (
        f"after ADD through telemetry.uptime.seconds the item is {after_add!r}, "
        f"expected exactly {expected_after_add!r}"
    )

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE #t.#a.#c :codes",
        ExpressionAttributeNames=alerts_names, ExpressionAttributeValues={":codes": {"SS": ["vibration"]}},
    )
    after_first_delete = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    expected_after_first_delete = {
        **key,
        "firmware": {"S": "v3"},
        "telemetry": {"M": {
            "uptime": {"M": {"seconds": {"N": "130"}}},
            "alerts": {"M": {"codes": {"SS": ["overheat"]}}},
        }},
    }
    assert _normalize_item(after_first_delete) == _normalize_item(expected_after_first_delete), (
        f"after DELETE of one element through telemetry.alerts.codes the item is "
        f"{after_first_delete!r}, expected exactly {expected_after_first_delete!r}"
    )

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE #t.#a.#c :codes",
        ExpressionAttributeNames=alerts_names, ExpressionAttributeValues={":codes": {"SS": ["overheat"]}},
    )
    after_second_delete = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    expected_after_second_delete = {
        **key,
        "firmware": {"S": "v3"},
        "telemetry": {"M": {
            "uptime": {"M": {"seconds": {"N": "130"}}},
            "alerts": {"M": {}},
        }},
    }
    assert _normalize_item(after_second_delete) == _normalize_item(expected_after_second_delete), (
        f"deleting the last element of telemetry.alerts.codes must drop that attribute and leave "
        f"telemetry.alerts as an empty map; got {after_second_delete!r}, expected exactly "
        f"{expected_after_second_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
