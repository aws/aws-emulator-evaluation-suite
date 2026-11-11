"""index-mapping-json-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "index-mapping-json-round-trip"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A complex index mapping written via CreateIndex is returned unchanged by
    GetIndex, and a subsequent UpdateIndex that adds a new field is merged in
    without disturbing the fields that were already there."""
    osc = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    collection_name = ctx.unique_name("sim2real-idxmap-")
    index_name = "sim2real-idx"

    enc_policy_name = _short_name(ctx, "sim2real-idxmapenc-")
    enc_doc = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
        "AWSOwnedKey": True,
    }
    osc.create_security_policy(type="encryption", name=enc_policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_security_policy(type="encryption", name=enc_policy_name)))

    collection_id = osc.create_collection(
        name=collection_name,
        type="SEARCH",
        standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": "idxmap-round-trip"}],
    )["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_collection(osc, collection_id))
    _wait_collection_active(osc, collection_id, timeout_s=600)

    _grant_index_data_access(ctx, osc, sts, collection_name)

    initial_schema = {
        "mappings": {
            "properties": {
                "title": {"type": "text"},
                "views": {"type": "integer"},
                "location": {"type": "geo_point"},
                "tags": {"type": "keyword"},
            }
        }
    }
    _poll_until(
        lambda: _try_create_index(osc, collection_id, index_name, initial_schema),
        lambda ok: ok,
        timeout_s=300,
        interval_s=10,
    )

    fetched_schema = _poll_until(
        lambda: _try_get_index(osc, collection_id, index_name),
        lambda schema: schema is not None,
        timeout_s=120,
        interval_s=5,
    )
    fetched_props = _extract_mappings(fetched_schema, index_name)["properties"]
    assert fetched_props == initial_schema["mappings"]["properties"], (
        f"mapping round trip mismatch: {fetched_props!r} != {initial_schema['mappings']['properties']!r}"
    )

    updated_properties = dict(initial_schema["mappings"]["properties"])
    updated_properties["rating"] = {"type": "float"}
    # Send only the new field, not the full merged set: UpdateIndex is additive, and the
    # point of this check is that AWS merges the delta with what CreateIndex already
    # stored rather than the client having to resend the untouched fields.
    _poll_until(
        lambda: _try_update_index(
            osc, collection_id, index_name, {"mappings": {"properties": {"rating": {"type": "float"}}}}
        ),
        lambda ok: ok,
        timeout_s=180,
        interval_s=10,
    )

    after_schema = _poll_until(
        lambda: _try_get_index(osc, collection_id, index_name),
        lambda schema: schema is not None
        and "rating" in _extract_mappings(schema, index_name).get("properties", {}),
        timeout_s=120,
        interval_s=5,
    )
    after_update = _extract_mappings(after_schema, index_name)["properties"]
    assert after_update == updated_properties, (
        f"mapping after UpdateIndex mismatch: {after_update!r} != {updated_properties!r}"
    )


# ===== self-contained helpers =====
def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _teardown(fn, timeout_s=135.0):
    """Teardown call: an absent resource is done, ConflictException (a collection still CREATING)
    or ValidationException (a policy still in use) is retried every 2 s to the deadline, which
    keeps all of the check's teardowns inside its cleanup budget; every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _best_effort_delete_collection(osc, collection_id):
    _teardown(lambda: osc.delete_collection(id=collection_id))


def _caller_principal_arn(sts):
    """Data access policy principals must be IAM role/user ARNs, not assumed-role session ARNs."""
    arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:
        account = arn.split(":")[4]
        role_name = arn.split("assumed-role/", 1)[1].split("/")[0]
        return f"arn:aws:iam::{account}:role/{role_name}"
    return arn


def _grant_index_data_access(ctx, osc, sts, collection_name):
    """Grants the current caller full data-plane permissions (collection + index) on
    `collection_name` via a data access policy, since CreateIndex/GetIndex/UpdateIndex/
    DeleteIndex are gated by aoss data access policies even for same-account IAM callers.
    Also attaches a network policy that admits only the aoss service: the proxy behind
    CreateIndex/GetIndex requires the collection to be network-reachable, not just data-access-granted."""
    principal = _caller_principal_arn(sts)
    policy_name = _short_name(ctx, "sim2real-idxmapdap-")
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
    osc.create_access_policy(type="data", name=policy_name, policy=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_access_policy(type="data", name=policy_name)))

    network_policy_name = _short_name(ctx, "sim2real-idxmapnet-")
    network_doc = [
        {
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
            "AllowFromPublic": False,
            "SourceServices": ["aoss.amazonaws.com"],
        }
    ]
    osc.create_security_policy(type="network", name=network_policy_name, policy=json.dumps(network_doc))
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_security_policy(type="network", name=network_policy_name)))


def _try_create_index(osc, collection_id, index_name, schema):
    try:
        osc.create_index(id=collection_id, indexName=index_name, indexSchema=schema)
        return True
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return False
        raise


def _try_update_index(osc, collection_id, index_name, schema):
    try:
        osc.update_index(id=collection_id, indexName=index_name, indexSchema=schema)
        return True
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return False
        raise


def _try_get_index(osc, collection_id, index_name):
    try:
        return osc.get_index(id=collection_id, indexName=index_name)["indexSchema"]
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return None
        raise


def _extract_mappings(schema, index_name):
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



def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last value: {last!r})")


def _wait_collection_active(osc, collection_id, timeout_s=600, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[collection_id]).get("collectionDetails", [])
        if details:
            status = details[0]["status"]
            if status == "ACTIVE":
                return
            if status == "FAILED":
                raise AssertionError(f"collection {collection_id} entered FAILED state while creating")
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
