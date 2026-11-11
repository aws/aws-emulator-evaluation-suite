"""lifecycle-policy-retention-window-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lifecycle-policy-retention-window-enforced"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearchserverless"]

_RETENTION = "48h"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetEffectiveLifecyclePolicy for an index of a TIMESERIES collection names the retention policy
    whose MinIndexRetention rule matches it, with retentionPeriod 48h and noMinRetentionPeriod not true.
    """
    client = ctx.client("opensearchserverless")
    coll_name = ctx.unique_name("sim2real-lp-coll-")
    lp_name = ctx.unique_name("sim2real-lp-")
    index_name = "idx1"

    enc_policy_name = _short_name(ctx, "sim2real-lp-enc-")
    enc_doc = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{coll_name}"]}],
        "AWSOwnedKey": True,
    }
    client.create_security_policy(type="encryption", name=enc_policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _quiet(lambda: client.delete_security_policy(type="encryption", name=enc_policy_name)))

    lp_doc = json.dumps(
        {
            "Rules": [
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{coll_name}/*"],
                    "MinIndexRetention": _RETENTION,
                }
            ]
        }
    )
    client.create_lifecycle_policy(type="retention", name=lp_name, policy=lp_doc)
    ctx.on_cleanup(lambda: _quiet(lambda: client.delete_lifecycle_policy(type="retention", name=lp_name)))

    detail = client.create_collection(
        name=coll_name,
        type="TIMESERIES",
        standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": "lifecycle-retention-window-enforced"}],
    )["createCollectionDetail"]
    collection_id = detail["id"]
    ctx.on_cleanup(lambda: _delete_collection_when_stable(ctx, collection_id))

    status = _poll_until(
        lambda: _collection_status(client, collection_id),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert status == "ACTIVE", f"collection never reached ACTIVE (last status {status!r})"

    _grant_index_data_access(ctx, client, coll_name)

    _poll_until(
        lambda: _try_create_index(client, collection_id, index_name),
        lambda ok: ok,
        timeout_s=300,
        interval_s=10,
    )
    # DeleteCollection removes the index with the collection; DeleteIndex on this index can answer
    # AccessDeniedException ("Access denied to delete index") even with aoss:DeleteIndex granted.

    resource_id = f"index/{coll_name}/{index_name}"
    resolved = _poll_until(
        lambda: client.batch_get_effective_lifecycle_policy(
            resourceIdentifiers=[{"type": "retention", "resource": resource_id}]
        ).get("effectiveLifecyclePolicyDetails", []),
        lambda details: len(details) == 1,
        timeout_s=120,
        interval_s=5,
    )
    effective = resolved[0]
    assert effective["type"] == "retention", f"expected type 'retention', got {effective.get('type')!r}"
    assert effective["resource"] == resource_id, (
        f"expected resource {resource_id!r}, got {effective.get('resource')!r}"
    )
    assert effective["policyName"] == lp_name, (
        f"expected effective policy to be {lp_name!r}, got {effective.get('policyName')!r}"
    )
    assert effective["retentionPeriod"] == _RETENTION, (
        f"expected effective retentionPeriod {_RETENTION!r}, got {effective.get('retentionPeriod')!r}"
    )
    assert not effective.get("noMinRetentionPeriod", False), (
        "expected noMinRetentionPeriod to be false since a MinIndexRetention rule matched this index"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last value: {last!r})")


def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _quiet(fn):
    """Teardown: a resource that is already gone is not an error."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _collection_status(client, collection_id):
    resp = client.batch_get_collection(ids=[collection_id])
    details = resp.get("collectionDetails", [])
    return details[0]["status"] if details else "GONE"


def _delete_collection_when_stable(ctx, collection_id, timeout_s=840.0, interval_s=2.0):
    """Delete the collection and its indexes once it settles (DeleteCollection refuses CREATING),
    then wait until BatchGetCollection stops listing it, all on one deadline inside the suite's
    900 s cleanup budget."""
    client = ctx.client("opensearchserverless")
    deadline = time.monotonic() + timeout_s
    while True:
        status = _collection_status(client, collection_id)
        if status == "GONE":
            return
        if status in ("ACTIVE", "FAILED"):
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(f"collection {collection_id} still {status} at the teardown deadline")
        time.sleep(interval_s)
    _quiet(lambda: client.delete_collection(id=collection_id))
    while True:
        status = _collection_status(client, collection_id)
        if status == "GONE":
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(f"collection {collection_id} still {status} at the teardown deadline")
        time.sleep(interval_s)


def _grant_index_data_access(ctx, client, coll_name):
    """Grants the account's IAM principals full data-plane permissions (collection + index) on
    `coll_name` via a data access policy, because CreateIndex/GetIndex/UpdateIndex/DeleteIndex
    are gated by aoss data access policies even for same-account IAM callers. Also attaches a
    network policy that admits only the aoss service: the proxy behind CreateIndex/GetIndex
    requires the collection to be network-reachable, not just data-access-granted."""
    principal = f"arn:aws:iam::{ctx.account}:root"
    access_policy_name = _short_name(ctx, "sim2real-lp-dap-")
    access_doc = [
        {
            "Rules": [
                {
                    "ResourceType": "collection",
                    "Resource": [f"collection/{coll_name}"],
                    "Permission": [
                        "aoss:CreateCollectionItems",
                        "aoss:DescribeCollectionItems",
                        "aoss:UpdateCollectionItems",
                    ],
                },
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{coll_name}/*"],
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
    client.create_access_policy(type="data", name=access_policy_name, policy=json.dumps(access_doc))
    ctx.on_cleanup(lambda: _quiet(lambda: client.delete_access_policy(type="data", name=access_policy_name)))

    network_policy_name = _short_name(ctx, "sim2real-lp-net-")
    network_doc = [
        {
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{coll_name}"]}],
            "AllowFromPublic": False,
            "SourceServices": ["aoss.amazonaws.com"],
        }
    ]
    client.create_security_policy(type="network", name=network_policy_name, policy=json.dumps(network_doc))
    ctx.on_cleanup(lambda: _quiet(lambda: client.delete_security_policy(type="network", name=network_policy_name)))


def _try_create_index(client, collection_id, index_name):
    try:
        client.create_index(id=collection_id, indexName=index_name)
        return True
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return False
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
