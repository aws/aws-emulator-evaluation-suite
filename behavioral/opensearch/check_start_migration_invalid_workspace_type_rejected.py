"""start-migration-invalid-workspace-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-migration-invalid-workspace-type-rejected"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMigration with an invalid workspace type fails with ValidationException and its exact message and
    records no migration, while a valid type on the same attached collection returns PENDING and lists.
    """
    osv = ctx.client("opensearch")

    collection_arn = _create_collection(ctx)

    app_name = _clean_name(ctx.unique_name("sim2osapp-"), 30)
    try:
        app = osv.create_application(
            name=app_name, tagList=[{"Key": "sim2real", "Value": CHECK}]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch Applications feature is not enabled for this account/region"
            ) from exc
        raise
    app_id = app["id"]
    ctx.on_cleanup(lambda: _delete_application(ctx, app_id))
    _wait_application_active(ctx, app_id, timeout_s=300.0)

    osv.attach_data_source(id=app_id, dataSourceArn=collection_arn)
    _poll_attachment_status(ctx, app_id, collection_arn, {"ATTACHED"}, {"FAILED"}, timeout_s=300.0)

    bogus_workspace = ctx.unique_name("sim2os-badws-")[:40]
    code, message = _error(
        lambda: osv.start_migration(
            applicationId=app_id,
            migrationOptions={
                "source": {"datasourceArn": collection_arn},
                "workspace": {
                    "createWorkspace": True,
                    "name": bogus_workspace,
                    "type": "NOT_A_REAL_WORKSPACE_TYPE",
                },
            },
        )
    )
    assert code == "ValidationException", f"unexpected error code {code!r} for invalid workspace type"
    expected_message = (
        "1 validation error detected: Value 'NOT_A_REAL_WORKSPACE_TYPE' at "
        "'migrationOptions.workspace.type' failed to satisfy constraint: Member must satisfy enum "
        "value set: [ALL, OBSERVABILITY, ESSENTIALS, SECURITY_ANALYTICS, SEARCH]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected call created no migration record for this application.
    migrations_after_reject = osv.list_migrations(applicationId=app_id)["migrations"]
    assert migrations_after_reject == [], (
        f"expected no migrations after the rejected StartMigration, got {migrations_after_reject!r}"
    )

    # Positive control: a valid workspace type on the same attached data source is accepted and
    # its migration is listed. Its progress state is transient, so only acceptance is graded.
    good_workspace = ctx.unique_name("sim2os-okws-")[:40]
    started = osv.start_migration(
        applicationId=app_id,
        migrationOptions={
            "source": {"datasourceArn": collection_arn},
            "workspace": {"createWorkspace": True, "name": good_workspace, "type": "SEARCH"},
        },
    )
    migration_id = started["migrationId"]
    assert migration_id, f"expected a migrationId from the accepted StartMigration, got {started!r}"
    assert started["status"] == "PENDING", f"expected PENDING status, got {started['status']!r}"

    migrations_after_success = osv.list_migrations(applicationId=app_id)["migrations"]
    assert any(m["migrationId"] == migration_id for m in migrations_after_success), (
        f"migration {migration_id!r} not found in ListMigrations {migrations_after_success!r}"
    )


def _clean_name(raw: str, max_len: int) -> str:
    cleaned = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:max_len]


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


def _create_collection(ctx) -> str:
    """A serverless SEARCH collection with its encryption and network policies, polled to ACTIVE;
    returns its ARN."""
    aoss = ctx.client("opensearchserverless")
    name = _clean_name("sim2real-osm-" + ctx.unique_name("c")[-10:], 28).rstrip("-")
    resource = [{"ResourceType": "collection", "Resource": [f"collection/{name}"]}]
    aoss.create_security_policy(
        name=name, type="encryption", policy=json.dumps({"Rules": resource, "AWSOwnedKey": True})
    )
    ctx.on_cleanup(lambda: aoss.delete_security_policy(name=name, type="encryption"))
    network_policy = {
        "Rules": resource,
        "AllowFromPublic": False,
        "SourceServices": ["application.opensearchservice.amazonaws.com"],
    }
    aoss.create_security_policy(name=name, type="network", policy=json.dumps([network_policy]))
    ctx.on_cleanup(lambda: aoss.delete_security_policy(name=name, type="network"))
    created = aoss.create_collection(name=name, type="SEARCH")["createCollectionDetail"]
    collection_id = created["id"]
    ctx.on_cleanup(lambda: aoss.delete_collection(id=collection_id))
    deadline = time.monotonic() + 900.0
    status = None
    while time.monotonic() < deadline:
        status = aoss.batch_get_collection(ids=[collection_id])["collectionDetails"][0]["status"]
        if status == "ACTIVE":
            return created["arn"]
        if status == "FAILED":
            raise AssertionError(f"collection {name} entered FAILED")
        time.sleep(2)
    raise AssertionError(f"collection {name} never became ACTIVE within 900s (last={status!r})")


def _delete_application(ctx, app_id: str) -> None:
    osv = ctx.client("opensearch")
    try:
        osv.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_application_active(ctx, app_id: str, timeout_s: float, interval_s: float = 10.0) -> dict:
    osv = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osv.get_application(id=app_id)
        if last["status"] == "ACTIVE":
            return last
        if last["status"] == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s (last={last})")


def _poll_attachment_status(ctx, app_id: str, data_source_arn: str, ok: set, bad: set, timeout_s: float, interval_s: float = 10.0) -> dict:
    osv = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osv.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)
        if last["status"] in ok:
            return last
        if last["status"] in bad:
            raise AssertionError(f"attachment {app_id}/{data_source_arn} entered {last['status']}")
        time.sleep(interval_s)
    raise AssertionError(f"attachment {app_id}/{data_source_arn} never reached {ok} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
