"""delete-collection-with-active-index-cascades."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-collection-with-active-index-cascades"
GROUP = "overly-permissive"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCollection on a collection holding an index answers DELETING, and once the collection is gone
    GetIndex fails with ResourceNotFoundException "The Collection with Id '<id>' does not exist.".
    """
    osc = ctx.client("opensearchserverless")
    collection_name = ctx.unique_name("sim2real-cascade-")
    index_name = "sim2real-idx"

    # CreateCollection requires a matching encryption security policy to exist first
    # ("No matching security policy of encryption type found for collection").
    enc_policy_name = _short_name(ctx, "sim2real-cascenc-")
    enc_doc = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
        "AWSOwnedKey": True,
    }
    osc.create_security_policy(type="encryption", name=enc_policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _quiet(lambda: osc.delete_security_policy(type="encryption", name=enc_policy_name)))

    collection_id = osc.create_collection(
        name=collection_name,
        type="SEARCH",
        standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": "audit"}],
    )["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_collection(osc, collection_id))
    _wait_collection_active(osc, collection_id, timeout_s=600)

    # CreateIndex/GetIndex go through a data-plane proxy that is gated by a data
    # access policy (even for same-account IAM callers) and requires the
    # collection to be network-reachable.
    _grant_index_data_access(ctx, osc, collection_name)

    _poll_until(
        lambda: _try_create_index(
            osc, collection_id, index_name, {"mappings": {"properties": {"title": {"type": "text"}}}}
        ),
        lambda ok: ok,
        timeout_s=300,
        interval_s=10,
    )

    # Positive control: the index is reachable while the collection is alive
    # (GetIndex can also lag data-access-policy propagation transiently).
    before_schema = _poll_until(
        lambda: _try_get_index(osc, collection_id, index_name),
        lambda schema: schema is not None,
        timeout_s=120,
        interval_s=5,
    )
    before_mappings = _extract_mappings(before_schema, index_name)
    actual_type = before_mappings["properties"]["title"]["type"]
    assert actual_type == "text", f"expected positive-control mapping type 'text', got {actual_type!r}"

    # Delete the collection despite it still holding an index; this must succeed
    # (cascade), not raise ConflictException.
    delete_resp = osc.delete_collection(id=collection_id)["deleteCollectionDetail"]
    assert delete_resp["id"] == collection_id, f"expected DeleteCollection to echo id {collection_id!r}, got {delete_resp['id']!r}"
    assert delete_resp["status"] == "DELETING", f"expected status 'DELETING' immediately after DeleteCollection, got {delete_resp['status']!r}"

    _wait_collection_removed(osc, collection_id, timeout_s=600)

    # The index must now be unreachable -- cascaded away with its collection,
    # not left dangling and independently accessible.
    code, message = _error(lambda: osc.get_index(id=collection_id, indexName=index_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"The Collection with Id '{collection_id}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _error(fn):
    """The (code, message) of the AWS error ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _quiet(fn):
    """Best-effort teardown: a resource that is already gone is not an error."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete_collection(osc, collection_id):
    _quiet(lambda: osc.delete_collection(id=collection_id))


def _grant_index_data_access(ctx, osc, collection_name):
    """Grants the account's IAM principals full data-plane permissions (collection + index) on
    `collection_name` via a data access policy, since CreateIndex/GetIndex/UpdateIndex/
    DeleteIndex are gated by aoss data access policies even for same-account IAM callers.
    Also attaches a network policy that admits only the aoss service: the proxy behind
    CreateIndex/GetIndex requires the collection to be network-reachable, not just data-access-granted."""
    principal = f"arn:aws:iam::{ctx.account}:root"
    policy_name = _short_name(ctx, "sim2real-cascdap-")
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
    ctx.on_cleanup(lambda: _quiet(lambda: osc.delete_access_policy(type="data", name=policy_name)))

    network_policy_name = _short_name(ctx, "sim2real-cascnet-")
    network_doc = [
        {
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
            "AllowFromPublic": False,
            "SourceServices": ["aoss.amazonaws.com"],
        }
    ]
    osc.create_security_policy(type="network", name=network_policy_name, policy=json.dumps(network_doc))
    ctx.on_cleanup(lambda: _quiet(lambda: osc.delete_security_policy(type="network", name=network_policy_name)))


def _try_create_index(osc, collection_id, index_name, schema):
    try:
        osc.create_index(id=collection_id, indexName=index_name, indexSchema=schema)
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


def _wait_collection_removed(osc, collection_id, timeout_s=600, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[collection_id]).get("collectionDetails", [])
        if not details:
            return
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} was never fully removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
