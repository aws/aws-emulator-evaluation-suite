"""index-update-schema-semantics."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "index-update-schema-semantics"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIndex applies mapping changes that are visible via GetIndex without disturbing
    existing settings; index settings are immutable after creation, and UpdateIndex rejects a
    settings-only change outright."""
    aos = ctx.client("opensearch")
    name = _create_minimal_domain(ctx)
    _wait_domain_active(ctx, name, timeout_s=2400.0)

    index_name = "sim2real-idx"
    # NOTE: use "keyword" fields (not "text") throughout -- CreateIndex/UpdateIndex's
    # automatic semantic enrichment feature targets text fields and isn't supported on
    # every engine version (including the one pinned below for fast provisioning).
    # Keyword mappings exercise the same create/update/get/delete schema semantics this
    # check cares about without depending on that feature.
    schema1 = {
        "mappings": {"properties": {"title": {"type": "keyword"}}},
        "settings": {"index": {"number_of_shards": "1", "number_of_replicas": "0"}},
    }
    create_resp = aos.create_index(DomainName=name, IndexName=index_name, IndexSchema=schema1)
    assert create_resp["Status"] == "CREATED", f"expected CREATED, got {create_resp['Status']!r}"
    ctx.on_cleanup(lambda: _safe_delete_index(ctx, name, index_name))

    # GetIndex echoes IndexSchema nested under the index name, unlike the flat {"mappings": ...,
    # "settings": ...} body CreateIndex/UpdateIndex accept as INPUT. IndexSchema is a Smithy
    # `document` (no fixed shape), so this nesting is measured, not documented -- see _dig_idx
    # below.
    got1 = _poll_until(
        lambda: aos.get_index(DomainName=name, IndexName=index_name)["IndexSchema"],
        lambda s: _dig_idx(s, index_name, ["mappings", "properties", "title", "type"]) == "keyword",
        timeout_s=90.0,
        interval_s=5.0,
    )
    title_type = _dig_idx(got1, index_name, ["mappings", "properties", "title", "type"])
    assert title_type == "keyword", f"expected title mapping type keyword, got {title_type!r}"
    replicas0 = str(_dig_idx(got1, index_name, ["settings", "index", "number_of_replicas"]))
    assert replicas0 == "0", f"expected number_of_replicas 0, got {replicas0!r}"

    # UpdateIndex rejects a settings change outright -- unlike CreateIndex, settings are fixed at
    # index creation and only mappings are mutable. schema2 is therefore mapping-only.
    schema2 = {
        "mappings": {
            "properties": {
                "title": {"type": "keyword"},
                "body": {"type": "keyword"},
            }
        },
    }
    update_resp = aos.update_index(DomainName=name, IndexName=index_name, IndexSchema=schema2)
    assert update_resp["Status"] == "UPDATED", f"expected UPDATED, got {update_resp['Status']!r}"

    got2 = _poll_until(
        lambda: aos.get_index(DomainName=name, IndexName=index_name)["IndexSchema"],
        lambda s: _dig_idx(s, index_name, ["mappings", "properties", "body", "type"]) == "keyword",
        timeout_s=90.0,
        interval_s=5.0,
    )
    title_type2 = _dig_idx(got2, index_name, ["mappings", "properties", "title", "type"])
    assert title_type2 == "keyword", (
        f"pre-existing mapping was lost by UpdateIndex: expected title type keyword, got {title_type2!r}"
    )
    replicas_unchanged = str(_dig_idx(got2, index_name, ["settings", "index", "number_of_replicas"]))
    assert replicas_unchanged == "0", (
        "a mapping-only UpdateIndex must not disturb settings: expected number_of_replicas "
        f"still 0, got {replicas_unchanged!r}"
    )

    # Positive control above (mapping-only UpdateIndex succeeds) isolates this negative to the
    # settings axis specifically, rather than "UpdateIndex rejects everything".
    settings_only_change = {"settings": {"index": {"number_of_replicas": "1"}}}
    settings_update_code, settings_update_message = _error(
        lambda: aos.update_index(
            DomainName=name, IndexName=index_name, IndexSchema=settings_only_change
        )
    )
    assert settings_update_code == "ValidationException", (
        "expected UpdateIndex to reject a settings-only change with ValidationException, got "
        f"{settings_update_code!r}"
    )
    assert settings_update_message == "Updates to index settings is not supported.", (
        f"unexpected settings-only UpdateIndex refusal message: {settings_update_message!r}"
    )

    delete_resp = aos.delete_index(DomainName=name, IndexName=index_name)
    assert delete_resp["Status"] == "DELETED", f"expected DELETED, got {delete_resp['Status']!r}"

    code, message = _poll_not_found(
        lambda: aos.get_index(DomainName=name, IndexName=index_name),
        timeout_s=30.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Resource index {index_name} does not exist", f"unexpected GetIndex not-found message: {message!r}"

    # Gone must also be unusable -- a mutation on the deleted index fails the same way a read does.
    update_code, update_message = _error(
        lambda: aos.update_index(DomainName=name, IndexName=index_name, IndexSchema=schema2)
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateIndex on a deleted index to fail ResourceNotFoundException, got {update_code!r}"
    )
    assert update_message == f"Resource index {index_name} does not exist", (
        f"unexpected UpdateIndex not-found message: {update_message!r}"
    )


def _dig(d, path):
    cur = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _dig_idx(schema, index_name, path):
    """GetIndex's IndexSchema nests everything under the index name; dig through that first."""
    return _dig(schema, [index_name, *path])


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_not_found(fn, timeout_s=30.0, interval_s=3.0):
    """Poll a read until it fails ResourceNotFoundException; return (code, message). Any other
    error is returned at once; a read that keeps succeeding raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"read still succeeded after {timeout_s}s: {last!r}")


def _create_minimal_domain(ctx, engine_version=None):
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-osb2-")
    account_id = sts.get_caller_identity()["Account"]
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*",
        }],
    })
    kwargs = dict(
        DomainName=name,
        # CreateIndex/UpdateIndex are validated against the domain's software version --
        # OpenSearch_2.13 (previously pinned here purely for fast provisioning) rejects them
        # outright with "Automatic Semantic Enrichment feature is not supported on this
        # software version", regardless of field types used in the schema. Use the newest
        # available engine version instead, which does support the index management API.
        EngineVersion=engine_version or _pick_latest_opensearch_version(ctx),
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=policy,
        TagList=[{"Key": "sim2real:check", "Value": "index-update-schema-semantics"}],
    )
    aos.create_domain(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name


def _pick_latest_opensearch_version(ctx):
    aos = ctx.client("opensearch")
    versions: list[str] = []
    resp = aos.list_versions(MaxResults=100)
    versions.extend(resp.get("Versions", []))
    while resp.get("NextToken"):
        resp = aos.list_versions(MaxResults=100, NextToken=resp["NextToken"])
        versions.extend(resp.get("Versions", []))

    def key(v):
        try:
            major, minor = v.split("_", 1)[1].split(".")
            return (int(major), int(minor))
        except Exception:
            return (0, 0)

    os_versions = sorted((v for v in versions if v.startswith("OpenSearch_")), key=key)
    return os_versions[-1] if os_versions else None



def _safe_delete_domain(ctx, name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_domain(DomainName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_index(ctx, domain_name, index_name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_index(DomainName=domain_name, IndexName=index_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s=2400.0):
    aos = ctx.client("opensearch")

    def probe():
        return aos.describe_domain(DomainName=name)["DomainStatus"]

    def done(s):
        return bool(s.get("Created")) and not s.get("Processing")

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=20.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
