"""batch-execute-statement-multi-attribute-gsi-select-rejected-per-slot."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-execute-statement-multi-attribute-gsi-select-rejected-per-slot"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_MULTI_HASH = "multi-hash-index"
_MULTI_ATTR_ERROR = (
    "ValidationError",
    "PartiQL statements cannot be executed on tables with multi-attribute HASH keys or "
    "multi-attribute RANGE keys.",
)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(read, done, *, budget_s: float, poll_s: float):
    """``read()`` once ``done(value)``; raises naming the last value when the budget runs out."""
    deadline = time.monotonic() + budget_s
    while True:
        value = read()
        if done(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {budget_s}s; last value {value!r}")
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchExecuteStatement SELECT slot addressed at a multi-attribute-HASH-key GSI reports a
    per-slot ValidationError naming the multi-attribute refusal, ahead of the generic rule a
    single-attribute index's WHERE clause would give; a sibling base-table slot still succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pq-bmak-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "tenant", "AttributeType": "S"},
            {"AttributeName": "region", "AttributeType": "S"},
            {"AttributeName": "ts", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": _MULTI_HASH,
                "KeySchema": [
                    {"AttributeName": "tenant", "KeyType": "HASH"},
                    {"AttributeName": "region", "KeyType": "HASH"},
                    {"AttributeName": "ts", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    desc = _poll(
        lambda: ddb.describe_table(TableName=table)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE" and all(g["IndexStatus"] == "ACTIVE" for g in t["GlobalSecondaryIndexes"]),
        budget_s=600.0, poll_s=5.0,
    )
    assert desc["GlobalSecondaryIndexes"][0]["IndexStatus"] == "ACTIVE", (
        f"expected the GSI active, got {desc['GlobalSecondaryIndexes']!r}"
    )

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "p1"}, "sk": {"S": "s1"}, "tenant": {"S": "acme"}, "region": {"S": "eu"}, "ts": {"S": "01"},
    })

    resp = ddb.batch_execute_statement(Statements=[
        # A WHERE clause naming only one of the two HASH attributes: on a single-attribute index
        # this shape is the generic "must specify the primary key" case, but the multi-attribute
        # refusal takes priority over that rule here.
        {"Statement": f'SELECT * FROM "{table}"."{_MULTI_HASH}" WHERE tenant=\'acme\''},
        {"Statement": f'SELECT * FROM "{table}" WHERE pk=\'p1\' AND sk=\'s1\''},
    ])
    responses = resp["Responses"]
    assert len(responses) == 2, f"expected 2 per-statement responses, got {len(responses)}: {responses}"

    bad = responses[0]
    assert "Item" not in bad, f"expected the multi-attribute GSI SELECT slot to carry no Item, got {bad}"
    error = bad.get("Error")
    assert error is not None, (
        f"expected the multi-attribute GSI SELECT to be reported as a per-slot Error "
        f"(not a thrown exception that would have aborted the whole batch), got {bad!r}"
    )
    assert (error.get("Code"), error.get("Message")) == _MULTI_ATTR_ERROR, (
        f"expected {_MULTI_ATTR_ERROR!r}, got {(error.get('Code'), error.get('Message'))!r}"
    )

    # Positive control: the sibling statement, addressed at the base table in the SAME batch
    # call, is unaffected by its neighbour's rejection.
    good = responses[1]
    assert "Error" not in good, f"expected the base-table SELECT to succeed, got {good}"
    assert good.get("Item", {}).get("tenant") == {"S": "acme"}, (
        f"expected the base-table SELECT to return the seeded item, got {good}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
