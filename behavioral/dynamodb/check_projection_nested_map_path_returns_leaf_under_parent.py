"""projection-nested-map-path-returns-leaf-under-parent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "projection-nested-map-path-returns-leaf-under-parent"
GROUP = "item_crud"
SERVICES = ["dynamodb"]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ProjectionExpression naming a path into a map returns the leaf still wrapped in its parent
    map, without its siblings, and omits the attribute entirely when the nested key is absent.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    _raw_get = ddb.get_item

    def _get(**kw):
        # Every GetItem below is legal, so a refusal is reported as an assertion failure.
        try:
            return _raw_get(**kw)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            raise AssertionError(
                f"ProjectionExpression {kw.get('ProjectionExpression')!r} is legal and must be "
                f"SERVED, but the target refused it with "
                f"{err.get('Code')}: {err.get('Message')}"
            ) from None

    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": "nested-map"},
            "profile": {
                "M": {
                    "city": {"S": "sea"},
                    "zip": {"S": "98101"},
                    "unit": {"M": {"floor": {"N": "7"}}},
                }
            },
            "unrelated": {"S": "untouched"},
        },
    )

    # --- one nested leaf: wrapped in its parent, no siblings, nothing else ---
    item = _get(
        TableName=table,
        Key={"pk": {"S": "nested-map"}},
        ConsistentRead=True,
        ProjectionExpression="#p.#c",
        ExpressionAttributeNames={"#p": "profile", "#c": "city"},
    )["Item"]

    assert item == {"profile": {"M": {"city": {"S": "sea"}}}}, (
        "a nested-map projection must return ONLY the selected leaf, still wrapped in its "
        f"parent map, and nothing else (no pk, no sibling keys); got {item!r}"
    )

    # --- two siblings under one parent: both kept, merged under the same parent ---
    both = _get(
        TableName=table,
        Key={"pk": {"S": "nested-map"}},
        ConsistentRead=True,
        ProjectionExpression="#p.#c, #p.#z",
        ExpressionAttributeNames={"#p": "profile", "#c": "city", "#z": "zip"},
    )["Item"]

    assert both == {"profile": {"M": {"city": {"S": "sea"}, "zip": {"S": "98101"}}}}, (
        "two sibling paths under one parent must merge into a single parent map carrying "
        f"both leaves; got {both!r}"
    )

    # --- a two-level path reaches through an intermediate map ---
    deep = _get(
        TableName=table,
        Key={"pk": {"S": "nested-map"}},
        ConsistentRead=True,
        ProjectionExpression="#p.#u.#f",
        ExpressionAttributeNames={"#p": "profile", "#u": "unit", "#f": "floor"},
    )["Item"]

    assert deep == {"profile": {"M": {"unit": {"M": {"floor": {"N": "7"}}}}}}, (
        "a two-level nested path must rebuild BOTH enclosing maps around the leaf; "
        f"got {deep!r}"
    )

    # --- an absent nested key omits the attribute, rather than returning an empty map ---
    missing = _get(
        TableName=table,
        Key={"pk": {"S": "nested-map"}},
        ConsistentRead=True,
        ProjectionExpression="#p.#nope",
        ExpressionAttributeNames={"#p": "profile", "#nope": "not_a_key"},
    )["Item"]

    assert missing == {}, (
        "a nested path naming a key the map does not have must omit the attribute "
        f"entirely, not return an empty parent map; got {missing!r}"
    )

    # --- control: projecting the parent itself returns the whole map unchanged ---
    whole = _get(
        TableName=table,
        Key={"pk": {"S": "nested-map"}},
        ConsistentRead=True,
        ProjectionExpression="#p",
        ExpressionAttributeNames={"#p": "profile"},
    )["Item"]

    assert whole == {
        "profile": {
            "M": {
                "city": {"S": "sea"},
                "zip": {"S": "98101"},
                "unit": {"M": {"floor": {"N": "7"}}},
            }
        }
    }, f"projecting the parent attribute must return the whole map unchanged; got {whole!r}"

    # --- control: an unprojected read still carries everything ---
    full = _get(
        TableName=table, Key={"pk": {"S": "nested-map"}}, ConsistentRead=True
    )["Item"]
    assert set(full) == {"pk", "profile", "unrelated"}, (
        f"an unprojected read must carry every attribute; got {sorted(full)}"
    )


def _create_table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-projnest-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _wait_table_active(ddb, name)
    return name


def _wait_table_active(ddb, name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {name} never became ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
