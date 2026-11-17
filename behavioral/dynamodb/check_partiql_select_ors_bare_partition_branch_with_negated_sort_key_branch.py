"""partiql-select-ors-bare-partition-branch-with-negated-sort-key-branch."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-select-ors-bare-partition-branch-with-negated-sort-key-branch"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _item(pk, sk):
    return {"pk": {"S": pk}, "sk": {"S": sk}}


def _select_all(ddb, statement):
    """Every item the statement returns, following NextToken."""
    items, token = [], None
    while True:
        kwargs = {"Statement": statement, "ConsistentRead": True}
        if token:
            kwargs["NextToken"] = token
        page = ddb.execute_statement(**kwargs)
        items.extend(page["Items"])
        token = page.get("NextToken")
        if not token:
            return items


def _ids(items):
    return sorted((i["pk"]["S"], i["sk"]["S"]) for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A WHERE clause ORing a bare partition-key branch with a negated sort-key branch on a
    different partition runs and returns their union, regardless of the branches' order.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlbareor-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    for pk in ("p", "q"):
        for sk in ("1", "2", "3"):
            ddb.put_item(TableName=table, Item=_item(pk, sk))
    # A sibling partition neither OR branch names, to prove no cross-partition leak.
    ddb.put_item(TableName=table, Item=_item("r", "1"))

    def select(where):
        return _ids(_select_all(ddb, f'SELECT * FROM "{table}" WHERE {where}'))

    # Positive control: the bare partition branch alone returns the whole partition.
    bare = select("pk = 'p'")
    assert bare == [("p", "1"), ("p", "2"), ("p", "3")], (
        f"pk = 'p' alone must return all of partition p, got {bare!r}"
    )

    # Positive control: the negated sort-key branch alone returns the complement on its partition.
    negated = select("pk = 'q' AND NOT sk = '2'")
    assert negated == [("q", "1"), ("q", "3")], (
        f"pk = 'q' AND NOT sk = '2' alone must return q's complement of sk 2, got {negated!r}"
    )

    expected = [("p", "1"), ("p", "2"), ("p", "3"), ("q", "1"), ("q", "3")]

    # The bare branch ORed with the negated branch runs and returns their union: all of p, plus
    # q's complement of sk 2 -- q's sk 2 and partition r stay excluded.
    union = select("pk = 'p' OR pk = 'q' AND NOT sk = '2'")
    assert union == expected, (
        f"pk = 'p' OR pk = 'q' AND NOT sk = '2' must return the union {expected!r}, got {union!r}"
    )

    # The same OR, branches swapped, must answer identically: OR is commutative here.
    swapped = select("pk = 'q' AND NOT sk = '2' OR pk = 'p'")
    assert swapped == expected, (
        f"pk = 'q' AND NOT sk = '2' OR pk = 'p' must return the same union {expected!r}, got "
        f"{swapped!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
