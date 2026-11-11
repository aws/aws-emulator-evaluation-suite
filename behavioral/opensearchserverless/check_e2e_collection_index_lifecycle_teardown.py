"""e2e-collection-index-lifecycle-teardown."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-collection-index-lifecycle-teardown"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tagged collection lists its tag and its index reports the 24h retention policy as effective; once the
    collection is deleted, GetIndex, ListTagsForResource and CreateIndex fail with ResourceNotFoundException and
    their exact messages, and ListCollections omits it.
    """
    aoss = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    coll_name = _short_name(ctx, "sim2real-e2ecoll")
    index_name = _short_name(ctx, "sim2real-e2eidx")
    policy_name = _short_name(ctx, "sim2real-e2elc")

    created = aoss.create_collection(
        name=coll_name,
        type="TIMESERIES",
        encryptionConfig={"aWSOwnedKey": True},
        tags=[{"key": "sim2real", "value": "e2e-teardown"}],
    )["createCollectionDetail"]
    collection_id = created["id"]
    collection_arn = created["arn"]

    def _cleanup_policy() -> None:
        try:
            aoss.delete_lifecycle_policy(type="retention", name=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_policy)

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

    tags = aoss.list_tags_for_resource(resourceArn=collection_arn)["tags"]
    assert {"key": "sim2real", "value": "e2e-teardown"} in tags, (
        f"expected the creation-time tag in ListTagsForResource, got {tags!r}"
    )

    schema = {"mappings": {"properties": {"title": {"type": "text"}}}}
    _poll_until(
        lambda: _try_create_index(aoss, collection_id, index_name, schema),
        lambda ok: ok,
        timeout_s=300,
        interval_s=10,
    )
    _poll_until(
        lambda: _try_get_index(aoss, collection_id, index_name),
        lambda ok: ok,
        timeout_s=120,
        interval_s=5,
    )


    policy_doc = json.dumps(
        {
            "Rules": [
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{coll_name}/*"],
                    "MinIndexRetention": "24h",
                }
            ]
        }
    )
    aoss.create_lifecycle_policy(type="retention", name=policy_name, policy=policy_doc)

    resource_id = f"index/{coll_name}/{index_name}"
    effective = _poll_until(
        lambda: aoss.batch_get_effective_lifecycle_policy(
            resourceIdentifiers=[{"type": "retention", "resource": resource_id}]
        ),
        lambda resp: bool(resp.get("effectiveLifecyclePolicyDetails")),
        timeout_s=120,
        interval_s=5,
    )
    detail = effective["effectiveLifecyclePolicyDetails"][0]
    assert detail["policyName"] == policy_name, (
        f"expected effective policy name {policy_name!r}, got {detail.get('policyName')!r}"
    )
    assert detail["resource"] == resource_id, (
        f"expected effective policy resource {resource_id!r}, got {detail.get('resource')!r}"
    )
    assert detail.get("retentionPeriod") == "24h", (
        f"expected retentionPeriod echoed as '24h', got {detail.get('retentionPeriod')!r}"
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
        f"expected GetIndex on the deleted collection to raise ResourceNotFoundException, got {code!r}"
    )
    expected_message = f"The Collection with Id '{collection_id}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tag_code, tag_message = _error(lambda: aoss.list_tags_for_resource(resourceArn=collection_arn))
    assert tag_code == "ResourceNotFoundException", (
        f"expected ListTagsForResource on the deleted collection to raise ResourceNotFoundException, "
        f"got {tag_code!r}"
    )
    expected_tag = f"Collection ID {collection_id} is not found"
    assert tag_message == expected_tag, f"expected message {expected_tag!r}, got {tag_message!r}"

    # A mutation on the dead id must also fail, not just a read.
    create_code, create_message = _error(
        lambda: aoss.create_index(id=collection_id, indexName=index_name, indexSchema=schema)
    )
    assert create_code == "ResourceNotFoundException", (
        f"expected CreateIndex against the deleted collection id to raise ResourceNotFoundException, "
        f"got {create_code!r}"
    )
    expected_create = f"The Collection with Id '{collection_id}' does not exist."
    assert create_message == expected_create, f"expected message {expected_create!r}, got {create_message!r}"

    listed_ids = {
        c["id"]
        for c in aoss.list_collections(collectionFilters={"name": coll_name})["collectionSummaries"]
    }
    assert collection_id not in listed_ids, (
        f"expected {collection_id!r} absent from ListCollections after delete, got {listed_ids!r}"
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


def _try_get_index(aoss: Any, collection_id: str, index_name: str) -> bool:
    try:
        aoss.get_index(id=collection_id, indexName=index_name)
        return True
    except Exception:
        return False


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
