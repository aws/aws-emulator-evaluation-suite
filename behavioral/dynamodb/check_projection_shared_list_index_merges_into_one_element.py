"""projection-shared-list-index-merges-into-one-element."""
from __future__ import annotations

import re

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "projection-shared-list-index-merges-into-one-element"
GROUP = "item_crud"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Projection paths through the same list index merge into one element carrying both leaves,
    while paths through different indices (including a different inner index) stay separate.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    ddb.put_item(
        TableName=table,
        Item={
            "pk": {"S": "shared-idx"},
            "rows": {
                "L": [
                    {"M": {"a": {"S": "a0"}, "b": {"S": "b0"}, "c": {"S": "c0"}}},
                    {"M": {"a": {"S": "a1"}, "b": {"S": "b1"}}},
                    {"M": {"a": {"S": "a2"}, "b": {"S": "b2"}}},
                ]
            },
            "outer": {
                "L": [
                    {
                        "M": {
                            "inner": {
                                "L": [
                                    {"M": {"p": {"S": "p00"}, "q": {"S": "q00"}}},
                                    {"M": {"p": {"S": "p01"}, "q": {"S": "q01"}}},
                                ]
                            }
                        }
                    }
                ]
            },
        },
    )

    names = {
        "#r": "rows",
        "#o": "outer",
        "#i": "inner",
        "#a": "a",
        "#b": "b",
        "#p": "p",
        "#q": "q",
    }

    def _used(expr: str) -> dict:
        """Only the aliases *expr* references; DynamoDB rejects unused ExpressionAttributeNames.

        Matched on token boundaries so `#a` is not considered used by `#ab`.
        """
        return {
            k: v for k, v in names.items()
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(k)}(?![A-Za-z0-9_])", expr)
        }

    def _project(expr: str):
        # A refused legal projection is a divergence, so report it as an assertion failure.
        try:
            return ddb.get_item(
                TableName=table,
                Key={"pk": {"S": "shared-idx"}},
                ConsistentRead=True,
                ProjectionExpression=expr,
                ExpressionAttributeNames=_used(expr),
            )["Item"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            raise AssertionError(
                f"ProjectionExpression {expr!r} is legal and must be SERVED, but the target "
                f"refused it with {err.get('Code')}: {err.get('Message')}"
            ) from None

    # --- same index, two leaves: ONE element carrying both, and not the third leaf ---
    merged = _project("#r[0].#a, #r[0].#b")
    assert merged == {"rows": {"L": [{"M": {"a": {"S": "a0"}, "b": {"S": "b0"}}}]}}, (
        "two paths through the SAME list index must merge into one response element "
        f"carrying both leaves (and not the unprojected sibling 'c'); got {merged!r}"
    )

    # --- order written must not change the merge ---
    merged_rev = _project("#r[0].#b, #r[0].#a")
    assert merged_rev == merged, (
        "the merge must not depend on the order the two paths were written; "
        f"got {merged_rev!r} vs {merged!r}"
    )

    # --- different indices: SEPARATE elements, compacted in index order ---
    split = _project("#r[0].#a, #r[2].#b")
    assert split == {
        "rows": {"L": [{"M": {"a": {"S": "a0"}}}, {"M": {"b": {"S": "b2"}}}]}
    }, (
        "paths through DIFFERENT indices must stay separate elements, compacted into "
        f"index order; got {split!r}"
    )

    # --- a shared index alongside a distinct one: merge the shared, keep the other ---
    mixed = _project("#r[0].#a, #r[0].#b, #r[2].#a")
    assert mixed == {
        "rows": {
            "L": [
                {"M": {"a": {"S": "a0"}, "b": {"S": "b0"}}},
                {"M": {"a": {"S": "a2"}}},
            ]
        }
    }, (
        "the shared index must merge into one element while a distinct index remains its "
        f"own, compacted next to it; got {mixed!r}"
    )

    # --- nested list, SAME inner index: merge ---
    inner_same = _project("#o[0].#i[0].#p, #o[0].#i[0].#q")
    assert inner_same == {
        "outer": {
            "L": [
                {
                    "M": {
                        "inner": {
                            "L": [{"M": {"p": {"S": "p00"}, "q": {"S": "q00"}}}]
                        }
                    }
                }
            ]
        }
    }, (
        "two paths sharing BOTH the outer and inner index must merge into one inner "
        f"element; got {inner_same!r}"
    )

    # --- nested list, DIFFERENT inner index: stay separate ---
    inner_split = _project("#o[0].#i[0].#p, #o[0].#i[1].#q")
    assert inner_split == {
        "outer": {
            "L": [
                {
                    "M": {
                        "inner": {
                            "L": [
                                {"M": {"p": {"S": "p00"}}},
                                {"M": {"q": {"S": "q01"}}},
                            ]
                        }
                    }
                }
            ]
        }
    }, (
        "paths sharing the outer index but differing on the INNER index must remain two "
        f"inner elements -- the merge key is the whole prefix; got {inner_split!r}"
    )

    # --- control: projecting a whole element returns every leaf it has ---
    whole = _project("#r[0]")
    assert whole == {
        "rows": {"L": [{"M": {"a": {"S": "a0"}, "b": {"S": "b0"}, "c": {"S": "c0"}}}]}
    }, f"projecting a whole element must return all of its leaves; got {whole!r}"

    # --- control: the stored item still has all three rows, unmerged ---
    stored = ddb.get_item(
        TableName=table, Key={"pk": {"S": "shared-idx"}}, ConsistentRead=True
    )["Item"]
    assert len(stored["rows"]["L"]) == 3, (
        f"a projected read must not mutate the stored list; got {stored['rows']!r}"
    )


def _create_table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-projmerge-")
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
