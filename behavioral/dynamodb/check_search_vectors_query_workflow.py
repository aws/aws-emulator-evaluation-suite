"""search-vectors-query-workflow."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-vectors-query-workflow"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchVectors on a vector-enabled table returns the nearest-neighbor
    items to a query vector, ranked by increasing Euclidean distance, matching
    the vectors written via PutItem."""
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-vec-")
    index_name = "vec-idx"

    try:
        ddb.create_table(
            TableName=table_name,
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
            VectorIndexes=[
                {
                    "IndexName": index_name,
                    "Dimensions": 4,
                    "DistanceFunction": "EUCLIDEAN",
                    "Projection": {"ProjectionType": "ALL"},
                    "VectorAttribute": {"AttributeName": "Embedding"},
                }
            ],
            Tags=[{"Key": "sim2real", "Value": "search-vectors-query-workflow"}],
        )
    except (ClientError, TypeError) as err:
        raise AssertionError(f"vector indexes not available in this account/region/SDK: {err}")
    ctx.on_cleanup(lambda: _delete_table_ignore(ddb, table_name))

    described = _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"],
        lambda t: t["TableStatus"] == "ACTIVE"
        and t.get("VectorIndexes")
        and t["VectorIndexes"][0]["IndexStatus"] == "ACTIVE",
        timeout_s=300,
        interval_s=5,
    )
    dims = described["VectorIndexes"][0]["Dimensions"]
    assert dims == 4, f"expected vector index dimensions 4, got {dims}"

    def _vec(values: list[float]) -> list[dict[str, str]]:
        return [{"N": str(v)} for v in values]

    ddb.put_item(
        TableName=table_name,
        Item={"pk": {"S": "near"}, "Embedding": {"L": _vec([0.0, 0.0, 0.0, 0.0])}},
    )
    ddb.put_item(
        TableName=table_name,
        Item={"pk": {"S": "mid"}, "Embedding": {"L": _vec([5.0, 5.0, 5.0, 5.0])}},
    )
    ddb.put_item(
        TableName=table_name,
        Item={"pk": {"S": "far"}, "Embedding": {"L": _vec([100.0, 100.0, 100.0, 100.0])}},
    )

    def _search() -> list[dict[str, Any]]:
        return ddb.search_vectors(
            TableName=table_name,
            IndexName=index_name,
            SearchVector=_vec([0.0, 0.0, 0.0, 0.0]),
            TopK=3,
        )["SearchResults"]

    results = _poll_until(
        _search,
        lambda r: len(r) == 3,
        timeout_s=180,
        interval_s=5,
    )
    ordered_pks = [r["Item"]["pk"]["S"] for r in results]
    assert ordered_pks == ["near", "mid", "far"], f"unexpected nearest-neighbor ordering: {ordered_pks}"
    scores = [float(r["Score"]) for r in results]
    assert scores[0] == 0.0, f"expected the exact-match item's score to be 0.0, got {scores[0]}"
    assert scores[0] < scores[1] < scores[2], f"expected strictly increasing distance scores, got {scores}"

    ddb.delete_table(TableName=table_name)

    def _describe_after_delete() -> tuple:
        try:
            return ddb.describe_table(TableName=table_name)["Table"]["TableStatus"], None
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")

    code, message = _poll_until(
        _describe_after_delete,
        lambda r: r[0] == "ResourceNotFoundException",
        timeout_s=180,
        interval_s=5,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Requested resource not found: Table: {table_name} not found"
    assert message == expected, f"unexpected DescribeTable message {message!r}"

    try:
        ddb.put_item(TableName=table_name, Item={"pk": {"S": "after-delete"}})
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected PutItem on a deleted table to be rejected as ResourceNotFoundException, "
            f"got {err.response['Error']['Code']}"
        )
        put_message = err.response["Error"].get("Message")
        assert put_message == "Requested resource not found", (
            f"unexpected PutItem message {put_message!r}"
        )
    else:
        raise AssertionError("PutItem succeeded against a deleted table")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _delete_table_ignore(ddb, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
