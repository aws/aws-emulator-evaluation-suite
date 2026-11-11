"""deleted-collection-cascades-to-indexes."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deleted-collection-cascades-to-indexes"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An index readable with its title:text mapping on an ACTIVE collection is gone once the collection is deleted:
    GetIndex and CreateIndex on the dead id fail with ResourceNotFoundException "The Collection with Id '<id>' does
    not exist." and ListCollections omits the collection.
    """
    aoss = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    coll_name = _short_name(ctx, "sim2real-casccoll")
    index_name = _short_name(ctx, "sim2real-cascidx")

    collection_id = aoss.create_collection(
        name=coll_name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": "cascade-audit"}],
    )["createCollectionDetail"]["id"]

    def _cleanup_collection() -> None:
        try:
            aoss.delete_collection(id=collection_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_collection)

    _grant_index_data_access(ctx, aoss, sts, coll_name)

    _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id])["collectionDetails"],
        lambda d: bool(d) and d[0]["status"] == "ACTIVE",
        timeout_s=1500,
        interval_s=20,
    )

    schema = {"mappings": {"properties": {"title": {"type": "text"}}}}
    _poll_until(
        lambda: _try_create_index(aoss, collection_id, index_name, schema),
        lambda ok: ok,
        timeout_s=300,
        interval_s=10,
    )
    # Positive control: the index is genuinely reachable, with the schema we asked
    # for, while the collection is still alive -- otherwise the later "gone"
    # assertion would be trivially true against a target that never built it.
    before_schema = _poll_until(
        lambda: _try_get_index(aoss, collection_id, index_name),
        lambda schema: schema is not None,
        timeout_s=120,
        interval_s=5,
    )
    before_mappings = _extract_mappings(before_schema, index_name)
    assert before_mappings["properties"]["title"]["type"] == "text", (
        f"expected index mapping to preserve title:text before delete, got {before_mappings!r}"
    )

    aoss.delete_collection(id=collection_id)
    _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id]),
        lambda resp: not resp["collectionDetails"] and bool(resp.get("collectionErrorDetails")),
        timeout_s=300,
        interval_s=10,
    )

    code, message = _error(lambda: aoss.get_index(id=collection_id, indexName=index_name))
    assert code == "ResourceNotFoundException", (
        f"expected GetIndex on the deleted collection to fail ResourceNotFoundException, got {code!r}"
    )
    expected_message = f"The Collection with Id '{collection_id}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    create_code, create_message = _error(
        lambda: aoss.create_index(id=collection_id, indexName=index_name, indexSchema=schema)
    )
    assert create_code == "ResourceNotFoundException", (
        "expected CreateIndex against the deleted collection id to also fail "
        f"ResourceNotFoundException (dead id must reject mutations, not just reads), got {create_code!r}"
    )
    expected_create = f"The Collection with Id '{collection_id}' does not exist."
    assert create_message == expected_create, f"expected message {expected_create!r}, got {create_message!r}"

    listed_ids = {
        c["id"]
        for c in aoss.list_collections(collectionFilters={"name": coll_name})["collectionSummaries"]
    }
    assert collection_id not in listed_ids, (
        f"expected deleted collection {collection_id!r} absent from "
        f"ListCollections(name={coll_name!r}), got ids={listed_ids!r}"
    )


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the error ``fn`` raises. An unexpected success raises AssertionError, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _try_get_index(aoss: Any, collection_id: str, index_name: str) -> dict[str, Any] | None:
    try:
        return aoss.get_index(id=collection_id, indexName=index_name)["indexSchema"]
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return None
        raise


def _extract_mappings(schema: dict[str, Any], index_name: str) -> dict[str, Any]:
    """GetIndex's indexSchema mirrors the OpenSearch `GET <index>` response, which nests
    mappings under the index name rather than exposing "mappings" at the top level."""
    if "mappings" in schema:
        return schema["mappings"]
    if isinstance(schema.get(index_name), dict) and "mappings" in schema[index_name]:
        return schema[index_name]["mappings"]
    for value in schema.values():
        if isinstance(value, dict) and "mappings" in value:
            return value["mappings"]
    raise KeyError(f"no mappings found in indexSchema: {schema!r}")


def _try_create_index(aoss: Any, collection_id: str, index_name: str, schema: dict[str, Any]) -> bool:
    try:
        aoss.create_index(id=collection_id, indexName=index_name, indexSchema=schema)
        return True
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return False
        raise


def _caller_principal_arn(sts: Any) -> str:
    arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        account = arn.split(":")[4]
        role_name = arn.split("assumed-role/", 1)[1].split("/")[0]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _grant_index_data_access(ctx: Any, aoss: Any, sts: Any, collection_name: str) -> str:
    principal = _caller_principal_arn(sts)
    policy_name = _short_name(ctx, "sim2real-idxdap")
    policy_doc = [
        {
            "Rules": [
                {
                    "ResourceType": "collection",
                    "Resource": [f"collection/{collection_name}"],
                    "Permission": [
                        "aoss:CreateCollectionItems",
                        "aoss:DescribeCollectionItems",
                        "aoss:UpdateCollectionItems",
                    ],
                },
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{collection_name}/*"],
                    "Permission": [
                        "aoss:CreateIndex",
                        "aoss:DescribeIndex",
                        "aoss:UpdateIndex",
                        "aoss:DeleteIndex",
                        "aoss:ReadDocument",
                        "aoss:WriteDocument",
                    ],
                },
            ],
            "Principal": [principal],
        }
    ]
    aoss.create_access_policy(type="data", name=policy_name, policy=json.dumps(policy_doc))
    ctx.on_cleanup(
        lambda: _safe(lambda: aoss.delete_access_policy(type="data", name=policy_name))
    )

    network_policy_name = _short_name(ctx, "sim2real-idxnet")
    network_doc = [
        {
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
            "AllowFromPublic": False,
            "SourceServices": ["aoss.amazonaws.com"],
        }
    ]
    aoss.create_security_policy(
        type="network", name=network_policy_name, policy=json.dumps(network_doc)
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: aoss.delete_security_policy(type="network", name=network_policy_name))
    )
    return policy_name



def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
