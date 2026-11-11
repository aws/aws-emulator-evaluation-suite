"""index-lifecycle-transitions."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "index-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An index created on an ACTIVE collection reads back its mapping and then its updated mapping, and once
    deleted, GetIndex and UpdateIndex fail with ResourceNotFoundException and its exact message.
    """
    aoss = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    coll_name = _short_name(ctx, "sim2real-idxcoll")
    index_name = _short_name(ctx, "sim2real-index")

    collection_id = aoss.create_collection(
        name=coll_name,
        type="SEARCH",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": "index-lifecycle-transitions"}],
    )["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_collection(id=collection_id)))

    _grant_index_data_access(ctx, aoss, sts, coll_name)

    _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id])["collectionDetails"],
        lambda d: bool(d) and d[0]["status"] == "ACTIVE",
        timeout_s=1500,
        interval_s=20,
    )

    schema_v1 = {"mappings": {"properties": {"title": {"type": "text"}}}}
    _poll_until(
        lambda: _try_create_index(aoss, collection_id, index_name, schema_v1),
        lambda ok: ok,
        timeout_s=300,
        interval_s=10,
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: aoss.delete_index(id=collection_id, indexName=index_name))
    )


    got = _poll_until(
        lambda: _try_get_index(aoss, collection_id, index_name),
        lambda schema: schema is not None,
        timeout_s=120,
        interval_s=5,
    )
    mappings1 = _extract_mappings(got, index_name)
    assert mappings1["properties"] == schema_v1["mappings"]["properties"], (
        f"initial mapping mismatch: got {mappings1['properties']!r}, "
        f"expected {schema_v1['mappings']['properties']!r}"
    )

    schema_v2 = {
        "mappings": {
            "properties": {"title": {"type": "text"}, "body": {"type": "text"}}
        }
    }
    _poll_until(
        lambda: _try_update_index(aoss, collection_id, index_name, schema_v2),
        lambda ok: ok,
        timeout_s=180,
        interval_s=10,
    )

    got2 = _poll_until(
        lambda: aoss.get_index(id=collection_id, indexName=index_name)["indexSchema"],
        lambda schema: "body"
        in _extract_mappings(schema, index_name).get("properties", {}),
        timeout_s=120,
        interval_s=5,
    )
    mappings2 = _extract_mappings(got2, index_name)
    assert mappings2["properties"] == schema_v2["mappings"]["properties"], (
        f"mapping after update mismatch: got {mappings2['properties']!r}, "
        f"expected {schema_v2['mappings']['properties']!r}"
    )

    aoss.delete_index(id=collection_id, indexName=index_name)

    _poll_until(
        lambda: _index_readable(aoss, collection_id, index_name),
        lambda readable: not readable,
        timeout_s=120,
        interval_s=5,
    )
    code, message = _error(lambda: aoss.get_index(id=collection_id, indexName=index_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted index, got {code!r}"
    )

    update_code, update_message = _error(
        lambda: aoss.update_index(id=collection_id, indexName=index_name, indexSchema=schema_v2)
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating deleted index, got {update_code!r}"
    )
    expected_message = f"Index not found: {index_name}"
    assert message == expected_message, f"expected GetIndex message {expected_message!r}, got {message!r}"
    assert update_message == expected_message, (
        f"expected UpdateIndex message {expected_message!r}, got {update_message!r}"
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


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _index_readable(aoss: Any, collection_id: str, index_name: str) -> bool:
    """True while GetIndex still succeeds; False once it is rejected."""
    try:
        aoss.get_index(id=collection_id, indexName=index_name)
    except Exception as exc:
        if getattr(exc, "response", None) is None:
            raise
        return False
    return True


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


def _try_get_index(aoss: Any, collection_id: str, index_name: str) -> dict[str, Any] | None:
    try:
        return aoss.get_index(id=collection_id, indexName=index_name)["indexSchema"]
    except Exception:
        return None


def _extract_mappings(schema: dict[str, Any], index_name: str) -> dict[str, Any]:
    """GetIndex's indexSchema mirrors the OpenSearch `GET <index>` response, which nests
    mappings under the index name (`{index_name: {"mappings": ..., "settings": ...}}`)
    rather than exposing "mappings" at the top level."""
    if "mappings" in schema:
        return schema["mappings"]
    if isinstance(schema.get(index_name), dict) and "mappings" in schema[index_name]:
        return schema[index_name]["mappings"]
    for value in schema.values():
        if isinstance(value, dict) and "mappings" in value:
            return value["mappings"]
    raise KeyError(f"no mappings found in indexSchema: {schema!r}")



def _try_create_index(aoss: Any, collection_id: str, index_name: str, schema: dict[str, Any]) -> bool:
    """Retries CreateIndex: data-access-policy propagation can lag a few seconds behind
    CreateAccessPolicy returning, surfacing transient AccessDeniedException."""
    try:
        aoss.create_index(id=collection_id, indexName=index_name, indexSchema=schema)
        return True
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return False
        raise


def _try_update_index(aoss: Any, collection_id: str, index_name: str, schema: dict[str, Any]) -> bool:
    """Same data-access-policy propagation lag as CreateIndex can surface here too."""
    try:
        aoss.update_index(id=collection_id, indexName=index_name, indexSchema=schema)
        return True
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return False
        raise



def _caller_principal_arn(sts: Any) -> str:
    """Data access policy principals must be IAM role/user ARNs, not assumed-role session ARNs."""
    arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        account = arn.split(":")[4]
        role_name = arn.split("assumed-role/", 1)[1].split("/")[0]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _grant_index_data_access(ctx: Any, aoss: Any, sts: Any, collection_name: str) -> str:
    """Grants the current caller full data-plane permissions (collection + index) on
    `collection_name` via a data access policy, since CreateIndex/GetIndex/UpdateIndex/
    DeleteIndex are gated by aoss data access policies even for same-account IAM callers.
    Also attaches a network policy that admits only the aoss service: the proxy behind
    CreateIndex/GetIndex requires the collection to be network-reachable, not just data-access-granted."""
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
