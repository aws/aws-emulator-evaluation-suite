"""e2e-migration-flow-status-progression."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-migration-flow-status-progression"
GROUP = "e2e"
SERVICES = ["opensearch"]

# GetMigration documents status as "Valid values are PENDING, IN_PROGRESS, SUCCEEDED, and FAILED."
_NON_TERMINAL = {"PENDING", "IN_PROGRESS"}
_TERMINAL = {"SUCCEEDED", "FAILED"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMigration's GetMigration status settles on a stable terminal value that ListMigrations
    reports identically under the same migrationId.
    """
    opensearch = ctx.client("opensearch")

    # The source must be a serverless collection linked via CreateApplication's dataSources, or
    # StartMigration fails ResourceNotFoundException; AttachDataSource is for domains only and
    # never settles for a collection ARN.
    source_arn = _create_collection(ctx)
    app_id = _create_application_linked_to(ctx, source_arn)
    _wait_application_active(ctx, app_id, timeout_s=180.0)

    workspace_name = ctx.unique_name("sim2real-behav-ws-")[:40]
    try:
        start = opensearch.start_migration(
            applicationId=app_id,
            migrationOptions={
                "source": {"datasourceArn": source_arn},
                "workspace": {"createWorkspace": True, "name": workspace_name, "type": "OBSERVABILITY"},
            },
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code == "DisabledOperationException":
            raise AssertionError("OpenSearch application migrations are not enabled for this account/region")
        raise AssertionError(
            f"StartMigration failed ({code}): {err.response['Error'].get('Message', '')}"
        ) from err

    migration_id = start["migrationId"]
    initial_status = start["status"]

    final_status = _poll_until_stable_terminal(
        lambda: opensearch.get_migration(migrationId=migration_id)["status"],
        timeout_s=100.0,
        interval_s=10.0,
    )
    assert final_status in _TERMINAL, (
        f"GetMigration never reached a documented terminal status ({sorted(_TERMINAL)}); "
        f"last={final_status!r}, initial={initial_status!r}"
    )

    listed = opensearch.list_migrations(applicationId=app_id)["migrations"]
    matches = [m for m in listed if m["migrationId"] == migration_id]
    assert len(matches) == 1, f"expected exactly one ListMigrations entry, found {len(matches)}"
    assert matches[0]["status"] == final_status, (
        f"ListMigrations status ({matches[0]['status']!r}) diverges from the stabilized "
        f"GetMigration status ({final_status!r}); initial status was {initial_status!r}"
    )


# ===== shared domain helpers =====


def _short_name(raw: str, max_len: int, min_len: int = 3) -> str:
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if len(name) > max_len:
        name = name[:max_len]
    name = name.rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name[1:]
    while len(name) < min_len:
        name += "0"
    return name


def _poll_until_stable_terminal(probe, timeout_s: float, interval_s: float, stable_reads: int = 3) -> Any:
    deadline = time.monotonic() + timeout_s
    history: list[Any] = []
    while time.monotonic() < deadline:
        value = probe()
        history.append(value)
        if (
            value not in _NON_TERMINAL
            and len(history) >= stable_reads
            and len(set(history[-stable_reads:])) == 1
        ):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"status never reached a stable terminal value within {timeout_s}s; history={history}")


def _create_application_linked_to(ctx, source_arn: str) -> str:
    opensearch = ctx.client("opensearch")
    app_name = _short_name(ctx.unique_name("aosappm"), 30)
    try:
        app = opensearch.create_application(
            name=app_name,
            dataSources=[{"dataSourceArn": source_arn}],
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch Applications feature is not enabled for this account/region"
            )
        raise
    app_id = app["id"]
    ctx.on_cleanup(lambda: _delete_application(ctx, app_id))
    return app_id


def _delete_application(ctx, app_id: str) -> None:
    opensearch = ctx.client("opensearch")
    _teardown_call(lambda: opensearch.delete_application(id=app_id))


def _wait_application_active(ctx, app_id: str, timeout_s: float, interval_s: float = 5.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s; last={status!r}")


def _create_collection(ctx) -> str:
    """Create a minimal serverless collection and its policies; wait for ACTIVE and return its ARN.

    Encryption is required to create it, network to reach ACTIVE, data access for the application.
    """
    aoss = ctx.client("opensearchserverless")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = _short_name(ctx.unique_name("sim2real-migsrc"), 32)

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

    create_resp = aoss.create_collection(name=name, type="SEARCH")
    detail = create_resp["createCollectionDetail"]
    collection_id = detail["id"]
    ctx.on_cleanup(lambda: _safe_delete_collection(aoss, collection_id))

    return _wait_collection_active(aoss, collection_id, timeout_s=200.0)


def _wait_collection_active(aoss, collection_id: str, timeout_s: float, interval_s: float = 10.0) -> str:
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
    raise AssertionError(f"collection {collection_id} never became ACTIVE within {timeout_s}s; last={last!r}")


def _teardown_call(fn, timeout_s: float = 300.0) -> None:
    """Run a teardown call: return on ResourceNotFoundException, retry a refusal while a dependent
    resource is still being released every 2 s to the deadline, raise anything else."""
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


def _safe_delete_collection(aoss, collection_id: str) -> None:
    _teardown_call(lambda: aoss.delete_collection(id=collection_id))


def _safe_delete_security_policy(aoss, name: str, policy_type: str) -> None:
    _teardown_call(lambda: aoss.delete_security_policy(name=name, type=policy_type))


def _safe_delete_access_policy(aoss, name: str) -> None:
    _teardown_call(lambda: aoss.delete_access_policy(name=name, type="data"))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
