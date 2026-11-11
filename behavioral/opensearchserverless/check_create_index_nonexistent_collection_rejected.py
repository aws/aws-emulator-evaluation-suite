"""create-index-nonexistent-collection-rejected."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-index-nonexistent-collection-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]

_FAKE_COLLECTION_ID = "0" * 20
_INDEX_SCHEMA = {"mappings": {"properties": {"title": {"type": "text"}}}}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIndex against a collection id that does not exist is rejected with
    ResourceNotFoundException and no index is created, while CreateIndex against a real, ACTIVE
    collection succeeds and the schema round-trips through GetIndex (positive control)."""
    aoss = ctx.client("opensearchserverless")
    index_name = "sim2real-idx"

    # negative: a collection id that doesn't exist is rejected
    code, message = _error(
        lambda: aoss.create_index(
            id=_FAKE_COLLECTION_ID, indexName=index_name, indexSchema=_INDEX_SCHEMA
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for CreateIndex against a nonexistent "
        f"collection id, got {code!r}"
    )
    expected_message = f"The Collection with Id '{_FAKE_COLLECTION_ID}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no index exists for that (nonexistent) collection either
    code2, message2 = _error(lambda: aoss.get_index(id=_FAKE_COLLECTION_ID, indexName=index_name))
    assert code2 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for GetIndex against a nonexistent "
        f"collection id, got {code2!r}"
    )
    assert message2 == expected_message, f"expected message {expected_message!r}, got {message2!r}"

    # positive control: a real, ACTIVE collection accepts CreateIndex and the schema round-trips
    name = _short_name(ctx, "sim2real-idxcol")
    created = aoss.create_collection(
        name=name,
        type="SEARCH",
        standbyReplicas="DISABLED",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": "audit"}],
    )["createCollectionDetail"]
    collection_id = created["id"]

    def _cleanup_collection() -> None:
        _delete_collection_when_stable(ctx, collection_id)

    ctx.on_cleanup(_cleanup_collection)

    _poll_until(
        lambda: aoss.batch_get_collection(ids=[collection_id])["collectionDetails"],
        lambda d: bool(d) and d[0]["status"] == "ACTIVE",
        timeout_s=600,
        interval_s=15,
    )

    sts = ctx.client("sts")
    _grant_index_data_access(ctx, aoss, sts, name)

    def _cleanup_index() -> None:
        try:
            aoss.delete_index(id=collection_id, indexName=index_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_index)

    _poll_until(
        lambda: _try_create_index(aoss, collection_id, index_name, _INDEX_SCHEMA),
        lambda created_ok: created_ok,
        timeout_s=300,
        interval_s=10,
    )
    fetched = _poll_until(
        lambda: _try_get_index(aoss, collection_id, index_name),
        lambda schema: schema is not None,
        timeout_s=120,
        interval_s=5,
    )
    mappings = _extract_mappings(fetched, index_name)
    actual_type = mappings["properties"]["title"]["type"]
    assert actual_type == "text", (
        f"expected GetIndex to round-trip mapping type 'text' for property 'title', "
        f"got {actual_type!r}"
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


def _try_get_index(aoss: Any, collection_id: str, index_name: str) -> dict[str, Any] | None:
    """Same data-access-policy propagation lag as CreateIndex can surface on the read path too."""
    try:
        return aoss.get_index(id=collection_id, indexName=index_name)["indexSchema"]
    except Exception:
        return None


def _caller_principal_arn(sts: Any) -> str:
    """Data access policy principals must be IAM role/user ARNs, not assumed-role session ARNs."""
    arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        account = arn.split(":")[4]
        role_name = arn.split("assumed-role/", 1)[1].split("/")[0]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _grant_index_data_access(ctx: Any, aoss: Any, sts: Any, collection_name: str) -> None:
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
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_access_policy(type="data", name=policy_name)))

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


def _delete_collection_when_stable(ctx, collection_id, timeout_s=900.0, interval_s=15.0):
    client = ctx.client("opensearchserverless")

    def probe():
        resp = client.batch_get_collection(ids=[collection_id])
        details = resp.get("collectionDetails", [])
        return details[0]["status"] if details else "GONE"

    status = _poll_until(
        probe, lambda s: s in ("ACTIVE", "FAILED", "GONE"), timeout_s=timeout_s, interval_s=interval_s
    )
    if status == "GONE":
        return
    try:
        client.delete_collection(id=collection_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
