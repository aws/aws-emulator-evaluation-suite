"""e2e-migration-full-lifecycle-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-migration-full-lifecycle-flow"
GROUP = "e2e"
SERVICES = ["opensearch"]

# Statuses that AWS may legitimately still be actively working through; anything
# outside this set ends the poll. GetMigration documents PENDING, IN_PROGRESS,
# SUCCEEDED and FAILED; a clean migration settles on SUCCEEDED.
_NON_TERMINAL = {"PENDING", "IN_PROGRESS", "CREATING", "RUNNING", "STARTING"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A started migration reaches SUCCEEDED in GetMigration with matching ids, source and counts,
    and ListMigrations reports the same status.
    """
    opensearch = ctx.client("opensearch")

    # The source must be a serverless collection (a domain ARN is a ValidationException) linked
    # through CreateApplication's dataSources; AttachDataSource never settles for a collection.
    ds_arn = _create_serverless_collection(ctx)
    app_id = _create_application(ctx, ds_arn)
    _wait_application_active(ctx, app_id, timeout_s=180.0)

    workspace_name = ctx.unique_name("sim2real-ws-")[:60]
    # The application-to-collection link propagates across services, so retry "not found".
    start_resp = _start_migration_once_visible(
        opensearch, app_id, ds_arn, workspace_name, timeout_s=180.0
    )
    migration_id = start_resp["migrationId"]

    final = _wait_migration_terminal(ctx, migration_id, timeout_s=300.0)
    assert final["status"] == "SUCCEEDED", f"migration settled on {final['status']!r}: {final!r}"
    assert final["migrationId"] == migration_id
    assert final["applicationId"] == app_id
    assert final["source"]["datasourceArn"] == ds_arn
    assert isinstance(final["exportedCount"], int) and final["exportedCount"] == final["importedCount"], (
        f"exportedCount {final['exportedCount']!r} vs importedCount {final['importedCount']!r} on a SUCCEEDED migration"
    )

    listed = opensearch.list_migrations(applicationId=app_id)["migrations"]
    matches = [m for m in listed if m["migrationId"] == migration_id]
    assert len(matches) == 1
    assert matches[0]["status"] == final["status"]


def _create_application(ctx, ds_arn: str) -> str:
    opensearch = ctx.client("opensearch")
    raw = ctx.unique_name("sim2real-mig-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = opensearch.create_application(name=name[:30], dataSources=[{"dataSourceArn": ds_arn}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))
    return app_id


def _compliant_collection_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:32].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "c" + cleaned
    return cleaned[:32]


def _create_serverless_collection(ctx) -> str:
    aoss = ctx.client("opensearchserverless")
    collection_name = _compliant_collection_name(ctx, "migcol")

    policy_name = collection_name  # policy name reused as the resource-matching name
    encryption_policy = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
        "AWSOwnedKey": True,
    }
    aoss.create_security_policy(
        name=policy_name,
        type="encryption",
        policy=json.dumps(encryption_policy),
    )
    ctx.on_cleanup(lambda: aoss.delete_security_policy(name=policy_name, type="encryption"))

    network_policy = [
        {
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{collection_name}"]}],
            "AllowFromPublic": False,
            "SourceServices": ["application.opensearchservice.amazonaws.com"],
        }
    ]
    aoss.create_security_policy(
        name=policy_name,
        type="network",
        policy=json.dumps(network_policy),
    )
    ctx.on_cleanup(lambda: aoss.delete_security_policy(name=policy_name, type="network"))

    # Without a data access policy StartMigration reports the collection as not found for the
    # application, not as an access error; the account root covers whichever principal reads it.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    aoss.create_access_policy(
        name=policy_name,
        type="data",
        policy=json.dumps(
            [
                {
                    "Rules": [
                        {
                            "ResourceType": "collection",
                            "Resource": [f"collection/{collection_name}"],
                            "Permission": [
                                "aoss:CreateCollectionItems",
                                "aoss:DeleteCollectionItems",
                                "aoss:UpdateCollectionItems",
                                "aoss:DescribeCollectionItems",
                            ],
                        },
                        {
                            "ResourceType": "index",
                            "Resource": [f"index/{collection_name}/*"],
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
    ctx.on_cleanup(lambda: aoss.delete_access_policy(name=policy_name, type="data"))

    create_resp = aoss.create_collection(name=collection_name, type="SEARCH")
    collection_id = create_resp["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: aoss.delete_collection(id=collection_id))

    return _wait_collection_active(ctx, collection_id, timeout_s=600.0)


def _wait_collection_active(ctx, collection_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    aoss = ctx.client("opensearchserverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        details = aoss.batch_get_collection(ids=[collection_id])["collectionDetails"]
        if details:
            last = details[0]
            if last["status"] == "ACTIVE":
                return last["arn"]
            if last["status"] == "FAILED":
                raise AssertionError(f"collection {collection_id} entered FAILED status")
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} never became ACTIVE; last={last}")


def _start_migration_once_visible(
    opensearch, app_id: str, ds_arn: str, workspace_name: str, timeout_s: float = 180.0, interval_s: float = 10.0
) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return opensearch.start_migration(
                applicationId=app_id,
                migrationOptions={
                    "source": {"datasourceArn": ds_arn},
                    "workspace": {"createWorkspace": True, "name": workspace_name, "type": "SEARCH"},
                },
            )
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            message = err.response.get("Error", {}).get("Message", "")
            if code != "ResourceNotFoundException" or "not found for application" not in message:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"StartMigration never saw collection {ds_arn} as attached to application "
                    f"{app_id} within {timeout_s}s (still: {message})"
                ) from err
            time.sleep(interval_s)


def _wait_migration_terminal(ctx, migration_id: str, timeout_s: float = 300.0, interval_s: float = 5.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.get_migration(migrationId=migration_id)
        if last["status"] not in _NON_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"migration {migration_id} never left non-terminal states; last={last}")


def _wait_application_active(ctx, app_id: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.get_application(id=app_id)["status"]
        if last == "ACTIVE":
            return
        if last == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never reached ACTIVE; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


