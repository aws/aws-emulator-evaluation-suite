"""concurrent-create-collection-same-name-single-winner."""
from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-collection-same-name-single-winner"
GROUP = "concurrency"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateCollection calls for the same name resolve to one winner, one ConflictException."""
    client = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-race-")

    # Prerequisite: AWS rejects CreateCollection with ValidationException unless a matching
    # encryption security policy already exists for the collection name.
    policy_name = ctx.unique_name("sim2real-race-pol-")
    enc_doc = {"Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}], "AWSOwnedKey": True}
    client.create_security_policy(type="encryption", name=policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _delete_security_policy(client, policy_name))

    def attempt(_idx):
        try:
            resp = client.create_collection(
                name=name,
                clientToken=str(uuid.uuid4()),
                tags=[{"key": "sim2real", "value": "audit"}],
            )
            return ("ok", resp["createCollectionDetail"]["id"])
        except ClientError as err:
            return ("err", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result() for f in [pool.submit(attempt, i) for i in range(2)]]

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, f"expected exactly one winner among concurrent creates, got {results}"
    assert len(errs) == 1, f"expected exactly one rejection among concurrent creates, got {results}"
    assert errs[0][1] == "ConflictException", (
        f"expected the losing concurrent CreateCollection to fail with ConflictException, got {errs[0][1]!r}"
    )
    expected = f"A collection with name '{name}' already exists."
    assert errs[0][2] == expected, f"expected the loser's message {expected!r}, got {errs[0][2]!r}"

    winner_id = oks[0][1]
    ctx.on_cleanup(lambda: _delete_collection(client, winner_id))

    # Positive control: exactly one collection was actually created under that name.
    got = client.batch_get_collection(names=[name])
    details = got.get("collectionDetails", [])
    assert len(details) == 1, f"expected exactly one persisted collection named {name!r}, got {details}"
    assert details[0]["id"] == winner_id, (
        f"expected the persisted collection named {name!r} to be the concurrent-create winner "
        f"{winner_id!r}, got {details[0]['id']!r}"
    )


def _delete_collection(client, collection_id, timeout_s=600.0):
    """Teardown: a collection still CREATING refuses DeleteCollection with ConflictException, retried
    every 2 s; then wait until BatchGetCollection no longer returns it, both to the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.delete_collection(id=collection_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while client.batch_get_collection(ids=[collection_id]).get("collectionDetails"):
        if time.monotonic() >= deadline:
            raise AssertionError(f"collection {collection_id} still listed {timeout_s}s after DeleteCollection")
        time.sleep(2)


def _delete_security_policy(client, policy_name):
    try:
        client.delete_security_policy(type="encryption", name=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
