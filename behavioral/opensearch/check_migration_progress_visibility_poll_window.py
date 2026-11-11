"""migration-progress-visibility-poll-window."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "migration-progress-visibility-poll-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For a migration from an attached serverless collection, two back-to-back GetMigration reads never
    regress exportedCount or importedCount, and ListMigrations reports the same status.
    """
    osv = ctx.client("opensearch")
    app_id = _create_application(ctx, osv)
    source_arn = _create_aoss_collection_arn(ctx)
    _attach_data_source(osv, app_id, source_arn)

    started = _call_with_backoff(
        osv.start_migration,
        applicationId=app_id,
        migrationOptions={
            "source": {"datasourceArn": source_arn},
            "workspace": {"createWorkspace": True, "name": ctx.unique_name("sim2real-ws-")},
        },
    )
    migration_id = started["migrationId"]

    # Two immediate, back-to-back reads: neither count may regress, and status must agree
    # between GetMigration and the corresponding ListMigrations entry.
    first = _call_with_backoff(osv.get_migration, migrationId=migration_id)
    second = _call_with_backoff(osv.get_migration, migrationId=migration_id)
    assert second["exportedCount"] >= first["exportedCount"], (
        f"exportedCount regressed across immediate re-polls: {first!r} -> {second!r}"
    )
    assert second["importedCount"] >= first["importedCount"], (
        f"importedCount regressed across immediate re-polls: {first!r} -> {second!r}"
    )

    listed = _call_with_backoff(osv.list_migrations, applicationId=app_id)["migrations"]
    matching = [m for m in listed if m["migrationId"] == migration_id]
    assert matching, f"migration {migration_id} missing from ListMigrations: {listed!r}"
    direct_status = _call_with_backoff(osv.get_migration, migrationId=migration_id)["status"]
    assert matching[0]["status"] == direct_status, (
        f"ListMigrations status {matching[0]['status']!r} disagrees with GetMigration "
        f"status {direct_status!r} for the same migrationId"
    )


def _call_with_backoff(fn, *args, retries: int = 6, base_delay: float = 3.0, **kwargs):
    """Retry on ThrottlingException with exponential backoff -- several checks in this suite
    create/poll OpenSearch applications concurrently, which can exceed the account's request
    rate for GetApplication/GetMigration and exhaust botocore's own retry budget."""
    last_err = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ThrottlingException":
                raise
            last_err = err
            if attempt < retries - 1:
                time.sleep(base_delay * (2**attempt))
    raise last_err


def _create_application(ctx, client) -> str:
    name = ctx.unique_name("sim2real-app-")
    resp = _call_with_backoff(
        client.create_application,
        name=name,
        tagList=[{"Key": "sim2real", "Value": "audit"}],
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_application(client, app_id))
    return app_id


def _safe_delete_application(client, app_id: str) -> None:
    """Delete the application and wait until GetApplication answers ResourceNotFoundException:
    DeleteApplication is asynchronous, and ConflictException (an operation in progress) is
    retried every 2 s. Raises at the 900 s teardown deadline."""
    deadline = time.monotonic() + 900.0
    while True:
        try:
            client.delete_application(id=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
                raise
        try:
            status = client.get_application(id=app_id).get("status")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"application {app_id} is still {status!r} at the teardown deadline")
        time.sleep(2)


def _create_aoss_collection_arn(ctx) -> str:
    """Create a minimal OpenSearch Serverless collection (encryption + network + a data
    access policy) and return its ARN, for use as a migration ``datasourceArn``. AOSS
    requires an encryption policy before CreateCollection will succeed and a network policy
    before the collection can settle into ACTIVE. Without a *data* access policy,
    AttachDataSource's PENDING -> ATTACHED settling never converges, since there is nothing
    for it to settle to -- so the account root is granted broad collection+index access.
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
        name=name, type="SEARCH", tags=[{"key": "sim2real", "value": "audit"}]
    )
    collection_id = resp["createCollectionDetail"]["id"]
    ctx.on_cleanup(lambda: _safe_delete_collection(aoss, collection_id))
    return resp["createCollectionDetail"]["arn"]


def _safe_delete_collection(aoss, collection_id: str) -> None:
    try:
        aoss.delete_collection(id=collection_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_security_policy(aoss, name: str, policy_type: str) -> None:
    try:
        aoss.delete_security_policy(name=name, type=policy_type)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_access_policy(aoss, name: str) -> None:
    try:
        aoss.delete_access_policy(name=name, type="data")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _attach_data_source(
    osv, app_id: str, data_source_arn: str, timeout_s: float = 1650.0, interval_s: float = 15.0
) -> None:
    """AttachDataSource is async/idempotent: fire it immediately and let one bounded loop
    absorb both its own transient not-ready rejections (the collection hasn't fully
    registered yet) and the subsequent PENDING -> ATTACHED settling -- rather than waiting
    for the application and the AOSS collection to individually reach ACTIVE first,
    sequentially, which sums two separate provisioning windows instead of overlapping them.
    """
    deadline = time.monotonic() + timeout_s
    attach_ok = False
    last = None
    while time.monotonic() < deadline:
        if not attach_ok:
            try:
                _call_with_backoff(osv.attach_data_source, id=app_id, dataSourceArn=data_source_arn)
                attach_ok = True
            except ClientError as err:
                if err.response.get("Error", {}).get("Code") not in (
                    "ResourceNotFoundException",
                    "ValidationException",
                ):
                    raise
                time.sleep(interval_s)
                continue
        last = _call_with_backoff(
            osv.describe_data_source_attachment, id=app_id, dataSourceArn=data_source_arn
        )["status"]
        if last in ("ATTACHED", "FAILED"):
            break
        time.sleep(interval_s)
    assert last == "ATTACHED", f"data source attachment landed in {last!r} instead of ATTACHED"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
