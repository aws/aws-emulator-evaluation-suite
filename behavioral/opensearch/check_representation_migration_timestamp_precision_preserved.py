"""representation-migration-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "representation-migration-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A migration's createdAt is identical in GetMigration, in its ListMigrations entry and in a repeat
    GetMigration read.
    """
    osv = ctx.client("opensearch")

    app_id = _create_application_no_wait(ctx)
    source_arn = _create_aoss_collection_arn_no_wait(ctx)
    _attach_data_source(osv, app_id, source_arn)

    started = _call_with_backoff(
        osv.start_migration,
        applicationId=app_id,
        migrationOptions={
            "source": {"datasourceArn": source_arn},
            "workspace": {
                "createWorkspace": True,
                "name": f"sim2real-ws-{uuid.uuid4().hex[:8]}",
                "type": "OBSERVABILITY",
            },
        },
    )
    migration_id = started["migrationId"]

    first_read = _call_with_backoff(osv.get_migration, migrationId=migration_id)
    created_at_first = first_read["createdAt"]

    entry = _find_migration(osv, app_id, migration_id)
    created_at_list = entry["createdAt"]
    assert created_at_list == created_at_first, (
        f"createdAt differs between GetMigration ({created_at_first!r}) and "
        f"ListMigrations ({created_at_list!r})"
    )

    second_read = _call_with_backoff(osv.get_migration, migrationId=migration_id)["createdAt"]
    assert second_read == created_at_first, (
        f"createdAt drifted across repeated GetMigration reads: "
        f"{created_at_first!r} != {second_read!r}"
    )


def _call_with_backoff(fn, *args, retries: int = 6, base_delay: float = 3.0, **kwargs):
    """Retry on ThrottlingException with exponential backoff.

    Several checks in this suite create/poll OpenSearch applications concurrently,
    which can exceed the account's request rate for GetApplication/GetMigration and
    exhaust botocore's own retry budget. Back off and retry those transient
    throttling errors ourselves instead of failing the check.
    """
    last_err = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ThrottlingException":
                raise
            last_err = err
            if attempt < retries - 1:
                time.sleep(base_delay * (2 ** attempt))
    raise last_err


def _attach_data_source(osv, app_id: str, data_source_arn: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    """Fire AttachDataSource immediately (it's async/idempotent: it accepts the call and
    returns PENDING even while the application and/or the AOSS collection are still coming
    up, then settles into ATTACHED once both are ready) and let ONE bounded loop absorb
    BOTH the attach call's own transient "not ready yet" rejections (ResourceNotFoundException
    / ValidationException, while the collection hasn't fully registered yet) and the
    subsequent PENDING -> ATTACHED settling -- rather than waiting for the application AND
    the AOSS collection to individually reach ACTIVE first, sequentially, which sums two
    separate provisioning windows instead of overlapping them.
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
                    "ResourceNotFoundException", "ValidationException",
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


def _create_aoss_collection_arn_no_wait(ctx) -> str:
    """Create a minimal OpenSearch Serverless collection (encryption + network + DATA ACCESS
    policy) and return its ARN, for use as a migration ``datasourceArn`` -- WITHOUT blocking on
    the collection reaching ACTIVE (the caller's merged attach/poll loop absorbs that).

    AOSS requires an encryption policy to exist before CreateCollection will succeed, and a
    network policy before the collection can settle into ACTIVE. Encryption + network policies
    alone only make the collection reachable/encrypted -- they grant no principal any read/write
    access to it. Without a *data* access policy, AttachDataSource's PENDING -> ATTACHED
    settling has been observed to never converge (there's nothing for it to settle TO, since
    the underlying access check never succeeds). Grant the account root broad collection+index
    access so whichever principal OpenSearch Applications uses under the hood to read the
    collection is covered.
    """
    aoss = ctx.client("opensearchserverless")
    name = ctx.unique_name("s2rmigts")[:32].lower()
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
        tags=[{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}],
    )
    detail = resp["createCollectionDetail"]
    collection_id = detail["id"]
    ctx.on_cleanup(lambda: _safe_delete_collection(aoss, collection_id))
    return detail["arn"]


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


def _create_application_no_wait(ctx) -> str:
    """Create the application WITHOUT blocking on it reaching ACTIVE -- the caller's merged
    attach/poll loop absorbs whatever provisioning time is left, instead of waiting for it here
    and then waiting AGAIN for the attachment."""
    osv = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = _call_with_backoff(
        osv.create_application,
        name=name,
        tagList=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_application(osv, app_id))
    return app_id


def _safe_delete_application(osv, app_id: str) -> None:
    """Delete the application and wait until GetApplication answers ResourceNotFoundException:
    DeleteApplication is asynchronous, and ConflictException (an operation in progress) is
    retried every 2 s. Raises at the 900 s teardown deadline."""
    deadline = time.monotonic() + 900.0
    while True:
        try:
            osv.delete_application(id=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
                raise
        try:
            status = osv.get_application(id=app_id).get("status")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"application {app_id} is still {status!r} at the teardown deadline")
        time.sleep(2)


def _find_migration(osv, app_id: str, migration_id: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        migrations = _call_with_backoff(osv.list_migrations, applicationId=app_id).get("migrations", [])
        for entry in migrations:
            if entry.get("migrationId") == migration_id:
                return entry
        time.sleep(3)
    raise AssertionError(f"migration {migration_id} never appeared in ListMigrations")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
