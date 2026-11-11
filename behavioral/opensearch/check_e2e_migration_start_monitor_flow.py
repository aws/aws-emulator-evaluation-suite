"""e2e-migration-start-monitor-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-migration-start-monitor-flow"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMigration from an AOSS collection returns PENDING, GetMigration settles on SUCCEEDED,
    and ListMigrations lists the same migration as SUCCEEDED for the application.
    """
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # StartMigration's source must be an AOSS collection ARN (a domain ARN is rejected), and it
    # must be one of the application's own data sources.
    source_arn = _create_aoss_collection_arn(ctx, account_id)

    app_name = ctx.unique_name("s2rmapp-")[:30].rstrip("-") or "s2rmappfallback"
    try:
        app = osc.create_application(
            name=app_name,
            dataSources=[{"dataSourceArn": source_arn}],
            tagList=[{"Key": "sim2real", "Value": CHECK}],
        )
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch application feature (direct-query/UI applications) is not "
                "enabled for this account/region"
            )
        raise
    app_id = app["id"]
    ctx.on_cleanup(lambda: _delete_application_quiet(osc, app_id))
    _wait_application_active(osc, app_id, timeout_s=300)

    try:
        started = osc.start_migration(
            applicationId=app_id,
            migrationOptions={
                "source": {"datasourceArn": source_arn},
                "workspace": {"createWorkspace": True, "name": "sim2real-migration-ws", "type": "SEARCH"},
            },
        )
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch saved-objects migration feature is not enabled for this "
                "account/region"
            )
        raise

    migration_id = started["migrationId"]
    assert started["status"] == "PENDING", (
        f"StartMigration returned initial status {started['status']!r}, expected 'PENDING'"
    )

    terminal_status = _wait_migration_terminal(osc, migration_id, timeout_s=600)
    assert terminal_status == "SUCCEEDED", (
        f"GetMigration settled on terminal status {terminal_status!r}, expected 'SUCCEEDED'"
    )

    migrations = osc.list_migrations(applicationId=app_id)["migrations"]
    matching = next((m for m in migrations if m["migrationId"] == migration_id), None)
    assert matching is not None, f"migration {migration_id} absent from ListMigrations: {migrations}"
    assert matching["status"] == "SUCCEEDED", (
        f"ListMigrations reported status {matching['status']!r} for {migration_id}, "
        f"expected the terminal 'SUCCEEDED' GetMigration reported"
    )
    assert matching["applicationId"] == app_id, (
        f"ListMigrations entry {migration_id} carries applicationId "
        f"{matching['applicationId']!r}, expected {app_id!r}"
    )


def _wait_application_active(osc, app_id, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.get_application(id=app_id)["status"]
        if last == "ACTIVE":
            return
        if last == "FAILED":
            raise AssertionError(f"application {app_id} failed to become ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s: last={last}")


def _create_aoss_collection_arn(ctx, account_id):
    """Create a minimal AOSS collection, wait until ACTIVE, and return its ARN. AOSS requires an
    encryption policy before CreateCollection and a network policy before it goes ACTIVE.
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
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_security_policy(name=name, type="encryption")))

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
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_security_policy(name=name, type="network")))

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
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_access_policy(name=name, type="data")))

    resp = aoss.create_collection(
        name=name, type="SEARCH", tags=[{"key": "sim2real", "value": CHECK}]
    )
    detail = resp["createCollectionDetail"]
    collection_id = detail["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aoss.delete_collection(id=collection_id)))
    return _wait_collection_active(aoss, collection_id)


def _wait_collection_active(aoss, collection_id, timeout_s=900.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        details = aoss.batch_get_collection(ids=[collection_id])["collectionDetails"]
        last = details[0]["status"] if details else None
        if last == "ACTIVE":
            return details[0]["arn"]
        if last == "FAILED":
            raise AssertionError(f"collection {collection_id} settled in FAILED instead of ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} never became ACTIVE within {timeout_s}s: last={last}")


_MIGRATION_TERMINAL = ("SUCCEEDED", "FAILED")


def _wait_migration_terminal(osc, migration_id, timeout_s=600.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.get_migration(migrationId=migration_id)["status"]
        if last in _MIGRATION_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"migration {migration_id} never reached a terminal state within {timeout_s}s: last={last}")


def _delete_application_quiet(osc, app_id):
    try:
        osc.delete_application(id=app_id)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code_from_exc(exc):
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
