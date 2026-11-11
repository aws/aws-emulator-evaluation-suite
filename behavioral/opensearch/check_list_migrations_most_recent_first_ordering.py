"""list-migrations-most-recent-first-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-migrations-most-recent-first-ordering"
GROUP = "ordering"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMigrations lists two sequential migrations of an AOSS-sourced application once each,
    in a stable order across repeated calls, with createdAt ordering them in start sequence.
    """
    osv = ctx.client("opensearch")
    app_id = _create_application_no_wait(ctx)
    source_arn = _create_aoss_collection_arn_no_wait(ctx)
    _attach_data_source(osv, app_id, source_arn)

    migration_ids = []
    for i in range(2):
        started = _call_with_backoff(
            osv.start_migration,
            applicationId=app_id,
            migrationOptions={
                "source": {"datasourceArn": source_arn},
                "workspace": {
                    "createWorkspace": True,
                    "name": ctx.unique_name(f"sim2real-ws-{i}-"),
                    "type": "OBSERVABILITY",
                },
                "conflictResolution": "CREATE_NEW_COPIES",
            },
        )
        migration_id = started["migrationId"]
        migration_ids.append(migration_id)
        _poll_migration_terminal(osv, migration_id)

    assert len(set(migration_ids)) == 2, f"expected two distinct migration jobs, got {migration_ids!r}"

    summaries = _call_with_backoff(osv.list_migrations, applicationId=app_id)["migrations"]
    listed_once = [m["migrationId"] for m in summaries]
    listed_twice = [
        m["migrationId"] for m in _call_with_backoff(osv.list_migrations, applicationId=app_id)["migrations"]
    ]

    assert listed_once == listed_twice, (
        f"ListMigrations order is not stable across repeated calls: {listed_once!r} vs {listed_twice!r}"
    )
    # ListMigrations documents no result order, so the listed createdAt values order the migrations;
    # two starts inside one timestamp tick share a value.
    ours = [m for m in summaries if m["migrationId"] in migration_ids]
    assert sorted(m["migrationId"] for m in ours) == sorted(migration_ids), (
        f"expected both migrations {migration_ids!r} listed once, got {ours!r}"
    )
    listed_created = {m["migrationId"]: m["createdAt"] for m in ours}
    assert listed_created[migration_ids[1]] >= listed_created[migration_ids[0]], (
        "expected createdAt in start order: "
        f"{listed_created[migration_ids[1]]} < {listed_created[migration_ids[0]]}"
    )


def _call_with_backoff(fn, *args, retries: int = 6, base_delay: float = 3.0, **kwargs):
    """Retry on ThrottlingException with exponential backoff.

    Several checks in this suite create/poll OpenSearch applications concurrently, which
    can exceed the account's request rate and exhaust botocore's own retry budget. Back off
    and retry those transient throttling errors ourselves instead of failing the check.
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


def _attach_data_source(osv, app_id: str, data_source_arn: str, timeout_s: float = 2100.0, interval_s: float = 15.0) -> None:
    """Fire AttachDataSource immediately (it's async/idempotent: it accepts the call and
    returns PENDING even while the application and/or the AOSS collection are still coming
    up, then settles into ATTACHED once both are ready) and let ONE bounded loop absorb
    BOTH the attach call's own transient "not ready yet" rejections (ResourceNotFoundException
    / ValidationException, while the collection hasn't fully registered yet) and the
    subsequent PENDING -> ATTACHED settling -- rather than waiting for the application AND
    the AOSS collection to individually reach ACTIVE first, sequentially, which sums two
    separate provisioning windows instead of overlapping them.

    StartMigration validates ``source.datasourceArn`` against the application's OWN
    attached-data-source registry, not the AOSS control plane directly -- an existing,
    ACTIVE AOSS collection that was never attached to the application is permanently
    rejected with ResourceNotFoundException ("Data source <arn> ... not found for
    application <id>"), no matter how long you wait for cross-service propagation.
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


def _poll_migration_terminal(osv, migration_id: str, timeout_s: float = 600.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _call_with_backoff(osv.get_migration, migrationId=migration_id)["status"]
        if last in ("SUCCEEDED", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"migration {migration_id} did not reach a terminal status within {timeout_s}s (last={last!r})")


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

    resp = aoss.create_collection(name=name, type="SEARCH")
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
        tagList=[{"Key": "sim2real", "Value": "list-migrations-most-recent-first-ordering"}],
    )
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_application(osv, app_id))
    return app_id


def _safe_delete_application(osv, app_id: str) -> None:
    try:
        osv.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
