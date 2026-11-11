"""projection-list-indices-compact-in-index-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "projection-list-indices-compact-in-index-order"
GROUP = "item_crud"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ProjectionExpression selecting list elements by index returns a dense list of only those
    elements, ordered by stored index (not written order) and renumbered from zero.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": "list-idx"},
            "slots": {
                "L": [
                    {"S": "zero"},
                    {"S": "one"},
                    {"S": "two"},
                    {"S": "three"},
                ]
            },
        },
    )

    def _project(expr: str):
        # A refusal of a legal projection is a divergence, so report it as an assertion failure.
        try:
            return ddb.get_item(
                TableName=table,
                Key={"pk": {"S": "list-idx"}},
                ConsistentRead=True,
                ProjectionExpression=expr,
                ExpressionAttributeNames={"#s": "slots"},
            )["Item"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            raise AssertionError(
                f"ProjectionExpression {expr!r} is legal and must be SERVED, but the target "
                f"refused it with {err.get('Code')}: {err.get('Message')}"
            ) from None

    # --- a single middle index lands at response position 0 ---
    one = _project("#s[2]")
    assert one == {"slots": {"L": [{"S": "two"}]}}, (
        "projecting a single list element must return a ONE-element list holding it at "
        f"response position 0 (not a sparse list padded to the original offset); got {one!r}"
    )

    # --- paths written out of index order come back in index order ---
    reordered = _project("#s[3], #s[1]")
    assert reordered == {"slots": {"L": [{"S": "one"}, {"S": "three"}]}}, (
        "list-element paths must be returned ordered by their index in the STORED list, "
        "not by the order the paths were written: '#s[3], #s[1]' must yield "
        f"[one, three]; got {reordered!r}"
    )

    # --- a non-contiguous pair is compacted to adjacent positions ---
    gapped = _project("#s[0], #s[3]")
    assert gapped == {"slots": {"L": [{"S": "zero"}, {"S": "three"}]}}, (
        "two non-adjacent indices must compact to response positions 0 and 1 with no hole "
        f"between them; got {gapped!r}"
    )

    # --- every index, ascending: the full list, unchanged ---
    everything = _project("#s[0], #s[1], #s[2], #s[3]")
    assert everything == {
        "slots": {"L": [{"S": "zero"}, {"S": "one"}, {"S": "two"}, {"S": "three"}]}
    }, f"projecting every index must reproduce the whole list in order; got {everything!r}"

    # --- control: projecting the attribute itself returns the whole list ---
    whole = _project("#s")
    assert whole == {
        "slots": {"L": [{"S": "zero"}, {"S": "one"}, {"S": "two"}, {"S": "three"}]}
    }, f"projecting the list attribute must return it unchanged; got {whole!r}"

    # --- control: the stored item is untouched by any of the reads above ---
    stored = ddb.get_item(
        TableName=table, Key={"pk": {"S": "list-idx"}}, ConsistentRead=True
    )["Item"]
    assert stored["slots"] == {
        "L": [{"S": "zero"}, {"S": "one"}, {"S": "two"}, {"S": "three"}]
    }, f"a projected read must not mutate the stored list; got {stored['slots']!r}"


def _create_table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-projidx-")
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
