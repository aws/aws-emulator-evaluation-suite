"""partiql-unicode-string-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "partiql-unicode-string-round-trip"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A unicode string value inserted via PartiQL INSERT is returned unchanged by a
    subsequent PartiQL SELECT."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    pk = ctx.unique_name("item-")
    text = "\u65e5\u672c\u8a9e \u0645\u0631\u062d\u0628\u0627 \U0001F680 caf\u00e9"

    ddb.execute_statement(
        Statement=f'INSERT INTO "{table}" VALUE {{\'pk\': ?, \'text\': ?}}',
        Parameters=[{"S": pk}, {"S": text}],
    )

    resp = ddb.execute_statement(
        Statement=f'SELECT text FROM "{table}" WHERE pk = ?',
        Parameters=[{"S": pk}],
    )
    items = resp["Items"]
    assert len(items) == 1, f"expected exactly one PartiQL result, got {len(items)}"
    assert items[0]["text"]["S"] == text, (
        f"unicode text mismatch: {items[0]['text']['S']!r} != {text!r}"
    )


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
