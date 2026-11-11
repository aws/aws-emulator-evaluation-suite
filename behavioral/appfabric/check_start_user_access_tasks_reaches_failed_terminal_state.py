"""start-user-access-tasks-reaches-failed-terminal-state."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "start-user-access-tasks-reaches-failed-terminal-state"
GROUP = "state"
SERVICES = ["appfabric"]


def _af_client(ctx, service: str = "appfabric"):
    """A client pinned to us-east-1, an AppFabric region (ctx.region need not be one); every
    resource this check creates lives in that one region."""
    from botocore.config import Config

    return ctx.client(
        service, region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _reset_appfabric(appfabric):
    """Defensively clear an app bundle an earlier corpus run left before this check runs. AppFabric enforces
    a hard, non-adjustable quota of ONE app bundle per account/region, so a bundle orphaned by an
    earlier interrupted run would block every check that follows it -- clear the decks first."""
    from botocore.exceptions import ClientError

    try:
        bundles = appfabric.list_app_bundles(maxResults=100).get("appBundleSummaryList", [])
    except ClientError:
        return
    for b in bundles:
        arn = b["arn"]
        try:
            tags = appfabric.list_tags_for_resource(resourceArn=arn).get("tags", [])
            if not any(t["key"].startswith("sim2real") or t["value"].startswith("sim2real") for t in tags):
                continue  # not a bundle this check created: leave it
            for auth in appfabric.list_app_authorizations(appBundleIdentifier=arn).get(
                "appAuthorizationSummaryList", []
            ):
                try:
                    appfabric.delete_app_authorization(
                        appBundleIdentifier=arn,
                        appAuthorizationIdentifier=auth["appAuthorizationArn"],
                    )
                except ClientError:
                    pass
            for ing in appfabric.list_ingestions(appBundleIdentifier=arn).get("ingestions", []):
                ing_arn = ing["arn"]
                try:
                    for dest in appfabric.list_ingestion_destinations(
                        appBundleIdentifier=arn, ingestionIdentifier=ing_arn
                    ).get("ingestionDestinations", []):
                        try:
                            appfabric.delete_ingestion_destination(
                                appBundleIdentifier=arn,
                                ingestionIdentifier=ing_arn,
                                ingestionDestinationIdentifier=dest["arn"],
                            )
                        except ClientError:
                            pass
                    try:
                        appfabric.stop_ingestion(appBundleIdentifier=arn, ingestionIdentifier=ing_arn)
                    except ClientError:
                        pass
                    appfabric.delete_ingestion(appBundleIdentifier=arn, ingestionIdentifier=ing_arn)
                except ClientError:
                    pass
            appfabric.delete_app_bundle(appBundleIdentifier=arn)
        except ClientError:
            pass


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartUserAccessTasks against an app authorization that is never Connected terminates as FAILED."""
    appfabric = _af_client(ctx)
    _reset_appfabric(appfabric)

    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()), tags=[{"key": "sim2real", "value": "behavioral"}]
    )["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    tenant_id = ctx.unique_name("sim2real-tenant-")
    auth_arn = appfabric.create_app_authorization(
        appBundleIdentifier=bundle_arn,
        app="SLACK",
        authType="oauth2",
        credential={
            "oauth2Credential": {
                "clientId": "placeholder-client-id",
                "clientSecret": "placeholder-client-secret",
            }
        },
        tenant={"tenantIdentifier": tenant_id, "tenantDisplayName": "sim2real behavioral tenant"},
        tags=[{"key": "sim2real", "value": "behavioral"}],
    )["appAuthorization"]["appAuthorizationArn"]
    ctx.on_cleanup(
        lambda: appfabric.delete_app_authorization(
            appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
        )
    )

    email = f"{ctx.unique_name('sim2real-user-')}@example.com"
    tasks = appfabric.start_user_access_tasks(appBundleIdentifier=bundle_arn, email=email)[
        "userAccessTasksList"
    ]
    assert len(tasks) >= 1
    item = tasks[0]

    if "taskId" not in item:
        # AppFabric rejected the lookup inline (no async task was ever started) because the
        # authorization was never Connected -- that inline error IS the "reaches failed" outcome.
        assert item.get("error", {}).get("errorCode"), item
        return

    task_id = item["taskId"]

    def _get_result():
        results = appfabric.batch_get_user_access_tasks(
            appBundleIdentifier=bundle_arn, taskIdList=[task_id]
        )["userAccessResultsList"]
        assert len(results) == 1
        return results[0]

    final = _poll_until(_get_result, lambda r: r["resultStatus"] != "IN_PROGRESS")
    assert final["resultStatus"] == "FAILED"
    assert final["taskError"]["errorCode"]



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

