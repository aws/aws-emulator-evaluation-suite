"""projection-shared-list-index-and-nested-map-merge-across-read-operations."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "projection-shared-list-index-and-nested-map-merge-across-read-operations"
GROUP = "item_crud"
SERVICES = ["dynamodb"]

_NAMES = {"#l": "l", "#m": "m", "#a": "a", "#b": "b", "#n": "n", "#x": "x", "#y": "y"}


def _used(expr: str) -> dict:
    """Only the aliases *expr* references; DynamoDB rejects unused ExpressionAttributeNames."""
    return {
        k: v for k, v in _NAMES.items()
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(k)}(?![A-Za-z0-9_])", expr)
    }


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ProjectionExpression sharing a list index across a leaf and a nested map path merges
    into one element on Query, Scan and BatchGetItem, and Query rebuilds a map leaf alongside a
    renumbered list element from two unrelated top-level paths.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "row"}, "sk": {"S": "only"}}

    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": "row"},
            "sk": {"S": "only"},
            "l": {
                "L": [
                    {
                        "M": {
                            "a": {"S": "a0"},
                            "b": {"S": "b0"},
                            "m": {"M": {"x": {"S": "mx0"}, "y": {"S": "my0"}}},
                        }
                    },
                    {"M": {"a": {"S": "a1"}, "b": {"S": "b1"}}},
                ]
            },
            "m": {"M": {"n": {"S": "n0"}, "z": {"S": "z0"}}},
        },
    )

    def _read(op: str, expr: str, *, extra_names: dict | None = None):
        aliases = {**_used(expr), **(extra_names or {})}
        try:
            if op == "GetItem":
                items = [ddb.get_item(
                    TableName=table, Key=key, ConsistentRead=True,
                    ProjectionExpression=expr, ExpressionAttributeNames=aliases,
                )["Item"]]
            elif op == "Query":
                items = ddb.query(
                    TableName=table,
                    KeyConditionExpression="#pk = :pk",
                    ExpressionAttributeNames={**aliases, "#pk": "pk"},
                    ExpressionAttributeValues={":pk": {"S": "row"}},
                    ProjectionExpression=expr, ConsistentRead=True,
                )["Items"]
            elif op == "Scan":
                items = ddb.scan(
                    TableName=table, ProjectionExpression=expr,
                    ExpressionAttributeNames=aliases, ConsistentRead=True,
                )["Items"]
            else:
                items = ddb.batch_get_item(RequestItems={table: {
                    "Keys": [key], "ProjectionExpression": expr,
                    "ExpressionAttributeNames": aliases, "ConsistentRead": True,
                }})["Responses"][table]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            raise AssertionError(
                f"{op} ProjectionExpression {expr!r} is legal and must be SERVED, but the target "
                f"refused it with {err.get('Code')}: {err.get('Message')}"
            ) from None
        assert len(items) == 1, f"{op} expected exactly one item, got {len(items)}: {items!r}"
        return items[0]

    # --- same list index shared by a leaf and Query/Scan/BatchGetItem: merge into one element ---
    expr_ab = "#l[0].#a, #l[0].#b"
    want_ab = {"l": {"L": [{"M": {"a": {"S": "a0"}, "b": {"S": "b0"}}}]}}
    for op in ("Query", "Scan", "BatchGetItem"):
        got = _read(op, expr_ab)
        assert got == want_ab, (
            f"{op} ProjectionExpression {expr_ab!r} must merge the shared index into one "
            f"element carrying both leaves; got {got!r}"
        )

    # --- GetItem: a leaf and a nested-map path through the SAME list index merge into one element ---
    expr_leaf_and_map = "#l[0].#a, #l[0].#m.#x"
    got_leaf_and_map = _read("GetItem", expr_leaf_and_map)
    assert got_leaf_and_map == {
        "l": {"L": [{"M": {"a": {"S": "a0"}, "m": {"M": {"x": {"S": "mx0"}}}}}]}
    }, (
        f"GetItem {expr_leaf_and_map!r} must merge the list-index leaf and the nested-map path "
        f"into one element; got {got_leaf_and_map!r}"
    )

    # --- GetItem: two nested-map leaves through the same list index merge into one map ---
    expr_map_pair = "#l[0].#m.#x, #l[0].#m.#y"
    got_map_pair = _read("GetItem", expr_map_pair)
    assert got_map_pair == {
        "l": {"L": [{"M": {"m": {"M": {"x": {"S": "mx0"}, "y": {"S": "my0"}}}}}]}
    }, (
        f"GetItem {expr_map_pair!r} must merge both nested-map leaves into one map under the "
        f"shared list element; got {got_map_pair!r}"
    )

    # --- Query: a map leaf and a different list index rebuild as two unrelated top-level paths ---
    expr_rebuild = "#m.#n, #l[1]"
    got_rebuild = _read("Query", expr_rebuild)
    assert got_rebuild == {
        "m": {"M": {"n": {"S": "n0"}}},
        "l": {"L": [{"M": {"a": {"S": "a1"}, "b": {"S": "b1"}}}]},
    }, (
        f"Query {expr_rebuild!r} must rebuild the map leaf and the renumbered list element as "
        f"two top-level paths; got {got_rebuild!r}"
    )

    # --- control: the stored item is untouched by any projected read above ---
    stored = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert stored["l"] == {
        "L": [
            {
                "M": {
                    "a": {"S": "a0"}, "b": {"S": "b0"},
                    "m": {"M": {"x": {"S": "mx0"}, "y": {"S": "my0"}}},
                }
            },
            {"M": {"a": {"S": "a1"}, "b": {"S": "b1"}}},
        ]
    }, f"a projected read must not mutate the stored list; got {stored['l']!r}"


def _create_table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-projmerge2-")
    ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
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
