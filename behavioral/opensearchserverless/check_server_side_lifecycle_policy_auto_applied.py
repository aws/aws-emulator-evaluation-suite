"""server-side-lifecycle-policy-auto-applied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "server-side-lifecycle-policy-auto-applied"
GROUP = "server-side"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a retention lifecycle policy is attached (only TIMESERIES collections
    support data lifecycle policies), BatchGetEffectiveLifecyclePolicy reflects it
    against the matching index without any further client action needed."""
    osc = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    collection_name = ctx.unique_name("sim2real-lifecycle-")
    index_name = "sim2real-idx"
    policy_name = _short_name(ctx, "sim2real-lcpol-")

    enc_policy_name = _short_name(ctx, "sim2real-lcenc-")
    enc_doc = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
        "AWSOwnedKey": True,
    }
    osc.create_security_policy(type="encryption", name=enc_policy_name, policy=json.dumps(enc_doc))
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_security_policy(type="encryption", name=enc_policy_name)))

    collection_id = osc.create_collection(
        name=collection_name,
        type="TIMESERIES",
        standbyReplicas="DISABLED",
        tags=[{"key": "sim2real", "value": "lifecycle-auto-applied"}],
    )["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_collection(osc, collection_id))
    _wait_collection_active(osc, collection_id, timeout_s=600)

    _grant_index_data_access(ctx, osc, sts, collection_name)

    _poll_until(
        lambda: _try_create_index(osc, collection_id, index_name),
        lambda ok: ok,
        timeout_s=300,
        interval_s=10,
    )

    resource_id = f"index/{collection_name}/{index_name}"
    policy_doc = {
        "Rules": [
            {"ResourceType": "index", "Resource": [resource_id], "MinIndexRetention": "24h"}
        ]
    }
    osc.create_lifecycle_policy(type="retention", name=policy_name, policy=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_lifecycle_policy(type="retention", name=policy_name)))

    effective = _poll_until(
        lambda: osc.batch_get_effective_lifecycle_policy(
            resourceIdentifiers=[{"type": "retention", "resource": resource_id}]
        ).get("effectiveLifecyclePolicyDetails", []),
        lambda details: len(details) == 1,
        timeout_s=120,
        interval_s=5,
    )
    detail = effective[0]
    assert detail["type"] == "retention", f"expected type 'retention', got {detail.get('type')!r}"
    assert detail["resource"] == resource_id, f"expected resource {resource_id!r}, got {detail.get('resource')!r}"
    assert detail["policyName"] == policy_name, (
        f"expected effective policy to be {policy_name!r}, got {detail.get('policyName')!r}"
    )
    assert detail.get("retentionPeriod") == "24h", (
        f"expected retentionPeriod '24h' auto-applied from the policy, got {detail.get('retentionPeriod')!r}"
    )
    assert not detail.get("noMinRetentionPeriod", False), (
        "expected noMinRetentionPeriod to be false since a MinIndexRetention rule matched this index"
    )


# ===== self-contained helpers =====
def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _teardown(fn, timeout_s=108.0):
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
    policy_name = _short_name(ctx, "sim2real-lcdap-")
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

    network_policy_name = _short_name(ctx, "sim2real-lcnet-")
    network_doc = [
        {
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
            "AllowFromPublic": False,
            "SourceServices": ["aoss.amazonaws.com"],
        }
    ]
    osc.create_security_policy(type="network", name=network_policy_name, policy=json.dumps(network_doc))
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_security_policy(type="network", name=network_policy_name)))


def _try_create_index(osc, collection_id, index_name):
    try:
        osc.create_index(id=collection_id, indexName=index_name)
        return True
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code == "AccessDeniedException":
            return False
        raise


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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
