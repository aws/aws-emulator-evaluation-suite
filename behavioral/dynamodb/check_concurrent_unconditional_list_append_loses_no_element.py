"""concurrent-unconditional-list-append-loses-no-element."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-unconditional-list-append-loses-no-element"
GROUP = "concurrency"
SERVICES = ["dynamodb"]

_WORKERS = 24
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


@tags("concern:data-plane", "dp:api", "plane:data", "axis:happy-path", "cap:c1")
def run(ctx) -> None:
    """24 concurrent unconditional list_append updates on one item lose no element, and each
    UPDATED_NEW post-image is a distinct-length prefix of the final list ending in its own token,
    proving DynamoDB serialises writes to one item.
    """
    ddb = ctx.client("dynamodb")
    # No SDK retries: list_append is not idempotent, so a retry of a landed request appends twice.
    racer = ctx.client(
        "dynamodb",
        config=Config(retries={"total_max_attempts": 1, "mode": "standard"},
                      max_pool_connections=_WORKERS),
    )
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "race"}}
    ddb.put_item(TableName=table, Item={**key, "l": {"L": []}})

    tokens = [f"w{i:02d}" for i in range(_WORKERS)]

    def _append(token):
        try:
            resp = racer.update_item(
                TableName=table, Key=key, UpdateExpression="SET l = list_append(l, :me)",
                ExpressionAttributeValues={":me": {"L": [{"S": token}]}},
                ReturnValues="UPDATED_NEW",
            )
        except ClientError as exc:
            return token, None, exc.response.get("Error", {}).get("Code")
        return token, [e["S"] for e in resp["Attributes"]["l"]["L"]], None

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        results = list(pool.map(_append, tokens))

    errors = [(t, code) for t, _, code in results if code is not None]
    assert errors == [], (
        f"{len(errors)} of {_WORKERS} unconditional appends were refused: {errors!r}; an "
        f"unconditional UpdateItem on one item has nothing to conflict on"
    )

    final = [e["S"] for e in ddb.get_item(
        TableName=table, Key=key, ConsistentRead=True)["Item"]["l"]["L"]]
    assert sorted(final) == sorted(tokens), (
        f"the stored list holds {len(final)} element(s) {final!r}; expected each of the "
        f"{_WORKERS} tokens exactly once -- a lost or duplicated append"
    )

    lengths = sorted(len(post) for _, post, _ in results)
    assert lengths == list(range(1, _WORKERS + 1)), (
        f"post-image lengths were {lengths!r}; expected each of 1..{_WORKERS} exactly once. Two "
        f"equal lengths mean two appends read the same list"
    )
    for token, post, _ in results:
        assert post[-1] == token, (
            f"worker {token!r}'s post-image {post!r} does not end with its own token"
        )
        assert final[:len(post)] == post, (
            f"worker {token!r}'s post-image {post!r} is not a prefix of the final list {final!r}; "
            f"the writes were not serialised"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
