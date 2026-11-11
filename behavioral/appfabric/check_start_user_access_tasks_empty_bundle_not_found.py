"""start-user-access-tasks-empty-bundle-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "start-user-access-tasks-empty-bundle-not-found"
GROUP = "error-semantics"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartUserAccessTasks against a bundle with no app authorizations at all returns an empty
    task list; the same call returns at least one task once an app authorization exists."""
    appfabric = _af_client(ctx)
    _reset_appfabric(appfabric)

    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()), tags=[{"key": "sim2real", "value": CHECK}]
    )["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    email = f"{ctx.unique_name('sim2real-user-')}@example.com"

    empty_tasks = appfabric.start_user_access_tasks(appBundleIdentifier=bundle_arn, email=email)[
        "userAccessTasksList"
    ]
    assert empty_tasks == []

    # Positive control: the same call returns at least one task once the bundle has an app
    # authorization configured.
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
    )["appAuthorization"]["appAuthorizationArn"]
    ctx.on_cleanup(
        lambda: appfabric.delete_app_authorization(
            appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
        )
    )

    tasks = appfabric.start_user_access_tasks(appBundleIdentifier=bundle_arn, email=email)[
        "userAccessTasksList"
    ]
    assert len(tasks) >= 1
    item = tasks[0]
    assert item["app"] == "SLACK"
    assert item["tenantId"] == tenant_id
    # The authorization is only PendingConnect (never actually Connected), so AppFabric may
    # either hand back an async taskId to poll, or fail the lookup immediately and report an
    # inline error -- either is a legitimate per-app/tenant task record, just not a silent no-op.
    assert item.get("taskId") or item.get("error", {}).get("errorCode"), item

    # Terminal read is independent of the call that started the task: when an async taskId
    # came back, confirm the record is discoverable through BatchGetUserAccessTasks rather than
    # trusting only StartUserAccessTasks's own response.
    task_id = item.get("taskId")
    if task_id:
        results = appfabric.batch_get_user_access_tasks(
            appBundleIdentifier=bundle_arn, taskIdList=[task_id]
        )["userAccessResultsList"]
        assert len(results) == 1, results
        fetched = results[0]
        assert fetched["app"] == "SLACK", fetched
        assert fetched["tenantId"] == tenant_id, fetched
        assert fetched["resultStatus"], fetched




if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
