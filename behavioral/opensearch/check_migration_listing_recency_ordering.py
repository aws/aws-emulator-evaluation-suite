"""migration-listing-recency-ordering."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "migration-listing-recency-ordering"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two sequential StartMigration calls get createdAt values in call order, and repeated
    ListMigrations calls list both once each, stably, with createdAt ordering them in call order.
    """
    opensearch = ctx.client("opensearch")

    app_name = _short_name("s2rmap", 30)
    app = opensearch.create_application(
        name=app_name,
        tagList=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": CHECK},
        ],
    )
    app_id = app["id"]
    ctx.on_cleanup(lambda: _delete_application(opensearch, app_id))

    source_arn = _create_aoss_collection_arn_no_wait(ctx)
    _attach_data_source(opensearch, app_id, source_arn)
    ctx.on_cleanup(lambda: _detach_quiet(opensearch, app_id, source_arn))

    migration_ids = []
    for i in range(2):
        started = opensearch.start_migration(
            applicationId=app_id,
            migrationOptions={
                "conflictResolution": "OVERWRITE",
                "source": {"datasourceArn": source_arn},
                "workspace": {"createWorkspace": True, "name": f"sim2real-ws-{i}-{uuid.uuid4().hex[:6]}"},
            },
        )
        migration_id = started["migrationId"]
        migration_ids.append(migration_id)
        # a migration must reach a terminal state before the application will
        # accept another StartMigration call (ConflictException otherwise)
        _wait_migration_terminal(opensearch, migration_id)

    assert len(set(migration_ids)) == 2, "expected two distinct migration jobs"

    first_created_at = opensearch.get_migration(migrationId=migration_ids[0])["createdAt"]
    second_created_at = opensearch.get_migration(migrationId=migration_ids[1])["createdAt"]
    assert second_created_at >= first_created_at, (
        "the second StartMigration call must be recorded with a createdAt at or "
        f"after the first: {second_created_at} < {first_created_at}"
    )

    listing_1 = opensearch.list_migrations(applicationId=app_id)["migrations"]
    listing_2 = opensearch.list_migrations(applicationId=app_id)["migrations"]
    ids_1 = [m["migrationId"] for m in listing_1]
    ids_2 = [m["migrationId"] for m in listing_2]

    assert set(migration_ids) <= set(ids_1), "both migrations must appear in the listing"
    assert ids_1 == ids_2, f"ListMigrations order was not stable across calls: {ids_1} != {ids_2}"

    # ListMigrations documents no result order, so the listed createdAt values order the migrations;
    # two starts inside one timestamp tick share a value.
    ours = [m for m in listing_1 if m["migrationId"] in migration_ids]
    assert sorted(m["migrationId"] for m in ours) == sorted(migration_ids), (
        f"ListMigrations must list both migrations once: expected {migration_ids!r}, got {ours!r}"
    )
    listed_created = {m["migrationId"]: m["createdAt"] for m in ours}
    assert listed_created[migration_ids[1]] >= listed_created[migration_ids[0]], (
        "ListMigrations must report createdAt in start order: "
        f"{listed_created[migration_ids[1]]} < {listed_created[migration_ids[0]]}"
    )


def _short_name(prefix: str, maxlen: int) -> str:
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}{suffix}"[:maxlen]


def _create_aoss_collection_arn_no_wait(ctx: Any) -> str:
    """Create a minimal OpenSearch Serverless collection (encryption + network + data
    access policy) and return its ARN, without blocking on it reaching ACTIVE -- the
    caller's AttachDataSource retry loop absorbs that settling time.
    """
    aoss = ctx.client("opensearchserverless")
    name = ctx.unique_name("s2rmigsrc")[:32].lower()
    if not name[0].isalpha():
        name = "c" + name[1:]

    aoss.create_security_policy(
        name=name,
        type="encryption",
        policy=json.dumps(
            {
                "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}],
                "AWSOwnedKey": True,
            }
        ),
    )
    ctx.on_cleanup(lambda: _safe_delete_security_policy(aoss, name, "encryption"))

    aoss.create_security_policy(
        name=name,
        type="network",
        policy=json.dumps(
            [
                {
                    "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}],
                    "AllowFromPublic": False,
                    "SourceServices": ["application.opensearchservice.amazonaws.com"],
                }
            ]
        ),
    )
    ctx.on_cleanup(lambda: _safe_delete_security_policy(aoss, name, "network"))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    aoss.create_access_policy(
        name=name,
        type="data",
        policy=json.dumps(
            [
                {
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": [f"collection/{name}"],
                            "Permission": [
                                "aoss:CreateCollectionItems",
                                "aoss:DeleteCollectionItems",
                                "aoss:UpdateCollectionItems",
                                "aoss:DescribeCollectionItems",
                            ],
                        },
                        {
                            "ResourceType": "index",
                            "Resource": [f"index/{name}/*"],
                            "Permission": [
                                "aoss:CreateIndex",
                                "aoss:DeleteIndex",
                                "aoss:UpdateIndex",
                                "aoss:DescribeIndex",
                                "aoss:ReadDocument",
                                "aoss:WriteDocument",
                            ],
                        },
                    ],
                    "Principal": [f"arn:aws:iam::{account_id}:root"],
                }
            ]
        ),
    )
    ctx.on_cleanup(lambda: _safe_delete_access_policy(aoss, name))

    resp = aoss.create_collection(
        name=name,
        type="SEARCH",
        tags=[
            {"key": "sim2real:managed", "value": "true"},
            {"key": "sim2real", "value": CHECK},
        ],
    )
    detail = resp["createCollectionDetail"]
    collection_id = detail["id"]
    ctx.on_cleanup(lambda: _safe_delete_collection(aoss, collection_id))
    return detail["arn"]


def _safe_delete_collection(aoss: Any, collection_id: str) -> None:
    try:
        aoss.delete_collection(id=collection_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_security_policy(aoss: Any, name: str, policy_type: str) -> None:
    try:
        aoss.delete_security_policy(name=name, type=policy_type)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_access_policy(aoss: Any, name: str) -> None:
    try:
        aoss.delete_access_policy(name=name, type="data")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _attach_data_source(
    opensearch: Any, app_id: str, data_source_arn: str, timeout_s: float = 900.0, interval_s: float = 15.0
) -> None:
    """Fire AttachDataSource and let one bounded loop absorb both its own transient
    not-ready rejections (the application and/or the AOSS collection still
    provisioning) and the subsequent PENDING -> ATTACHED settling.
    """
    deadline = time.monotonic() + timeout_s
    attach_ok = False
    last = None
    while time.monotonic() < deadline:
        if not attach_ok:
            try:
                opensearch.attach_data_source(id=app_id, dataSourceArn=data_source_arn)
                attach_ok = True
            except ClientError as err:
                if err.response.get("Error", {}).get("Code") not in (
                    "ResourceNotFoundException", "ValidationException",
                ):
                    raise
                time.sleep(interval_s)
                continue
        last = opensearch.describe_data_source_attachment(
            id=app_id, dataSourceArn=data_source_arn
        )["status"]
        if last in ("ATTACHED", "FAILED"):
            break
        time.sleep(interval_s)
    assert last == "ATTACHED", f"data source attachment landed in {last!r} instead of ATTACHED"


def _delete_application(opensearch: Any, app_id: str) -> None:
    try:
        opensearch.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _detach_quiet(opensearch: Any, app_id: str, data_source_arn: str) -> None:
    try:
        opensearch.detach_data_source(id=app_id, dataSourceArn=data_source_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_migration_terminal(opensearch: Any, migration_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = opensearch.get_migration(migrationId=migration_id)["status"]
        if status in ("SUCCEEDED", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"migration {migration_id} did not reach a terminal state within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
