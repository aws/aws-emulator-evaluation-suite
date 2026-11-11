"""list-index-past-end-set-appends-and-remove-shifts."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-index-past-end-set-appends-and-remove-shifts"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0

def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"dynamodb table {table_name!r} could not be deleted: {code}"
                ) from exc
            return


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, name))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return name
        time.sleep(2.0)
    raise AssertionError(f"table {name!r} not ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s: {status!r}")


def _strings(attr):
    return [e["S"] for e in attr["L"]]


@tags("concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """SET at a list index past the end appends (UPDATED_NEW returns nothing, as l[10] does not
    exist), REMOVE past the end is a no-op, and REMOVE inside the list shifts the tail left with
    UPDATED_NEW reporting the element now at that index."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "list"}}
    ddb.put_item(TableName=table, Item={**key, "l": {"L": [{"S": "x"}, {"S": "y"}, {"S": "z"}]}})

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET l[10] = :v",
        ExpressionAttributeValues={":v": {"S": "w"}}, ReturnValues="UPDATED_NEW",
    )
    assert "Attributes" not in resp, (
        f"SET l[10] with ReturnValues=UPDATED_NEW returned Attributes {resp.get('Attributes')!r}; "
        f"real AWS returns none, because the element is appended at l[3] and the path l[10] it "
        f"names does not exist after the write"
    )
    after_set = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]["l"]
    assert _strings(after_set) == ["x", "y", "z", "w"], (
        f"after SET l[10] on a 3-element list the list is {after_set!r}; expected the value "
        f"APPENDED as the 4th element -- no padding, no sparse index"
    )

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="REMOVE l[10]", ReturnValues="ALL_NEW",
    )
    assert _strings(resp["Attributes"]["l"]) == ["x", "y", "z", "w"], (
        f"REMOVE l[10] on a 4-element list returned ALL_NEW l={resp['Attributes'].get('l')!r}; "
        f"removing past the end is a no-op, not an error and not a truncation"
    )

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="REMOVE l[1]", ReturnValues="UPDATED_NEW",
    )
    assert resp.get("Attributes") == {"l": {"L": [{"S": "z"}]}}, (
        f"REMOVE l[1] with UPDATED_NEW returned {resp.get('Attributes')!r}; expected l=[z], the "
        f"element that shifted into index 1"
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]["l"]
    assert _strings(final) == ["x", "z", "w"], (
        f"after REMOVE l[1] the list is {final!r}; expected the tail shifted left to [x, z, w] "
        f"with no hole"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
