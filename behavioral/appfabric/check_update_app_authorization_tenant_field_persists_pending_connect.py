"""update-app-authorization-tenant-field-persists-pending-connect."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-app-authorization-tenant-field-persists-pending-connect"
GROUP = "state"
SERVICES = ["appfabric"]


def _af_client(ctx, service: str = "appfabric"):
    """AppFabric serves only us-east-1, eu-west-1 and ap-northeast-1 and ctx.region may be
    none of them, so every target gets a ctx.client pinned to us-east-1."""
    from botocore.config import Config

    return ctx.client(
        service,
        region="us-east-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
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
    """UpdateAppAuthorization persists new tenant display name and leaves a PendingConnect status untouched."""
    appfabric = _af_client(ctx)
    _reset_appfabric(appfabric)

    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()),
        tags=[{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behavioral"}],
    )["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    tenant_id = ctx.unique_name("sim2real-tenant-")
    created = appfabric.create_app_authorization(
        appBundleIdentifier=bundle_arn,
        app="SLACK",
        authType="oauth2",
        credential={
            "oauth2Credential": {
                "clientId": "placeholder-client-id",
                "clientSecret": "placeholder-client-secret",
            }
        },
        tenant={"tenantIdentifier": tenant_id, "tenantDisplayName": "original-display-name"},
        tags=[{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behavioral"}],
    )["appAuthorization"]

    auth_arn = created["appAuthorizationArn"]
    ctx.on_cleanup(
        lambda: appfabric.delete_app_authorization(
            appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
        )
    )
    assert created["status"] == "PendingConnect", (
        f"expected a freshly created app authorization to start PendingConnect, got {created['status']!r}"
    )

    updated = appfabric.update_app_authorization(
        appBundleIdentifier=bundle_arn,
        appAuthorizationIdentifier=auth_arn,
        tenant={"tenantIdentifier": tenant_id, "tenantDisplayName": "updated-display-name"},
    )["appAuthorization"]

    assert updated["tenant"]["tenantDisplayName"] == "updated-display-name", (
        "expected UpdateAppAuthorization's own response to reflect the new tenant display name, "
        f"got {updated['tenant']['tenantDisplayName']!r}"
    )
    # It was never connected, so updating it cannot "reset" a connected state -- it just stays PendingConnect.
    assert updated["status"] == "PendingConnect", (
        f"expected status to remain PendingConnect across the update, got {updated['status']!r}"
    )

    fetched = appfabric.get_app_authorization(
        appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
    )["appAuthorization"]
    assert fetched["tenant"]["tenantDisplayName"] == "updated-display-name", (
        "expected an independent GetAppAuthorization read to reflect the persisted tenant "
        f"display name, got {fetched['tenant']['tenantDisplayName']!r}"
    )
    assert fetched["status"] == "PendingConnect", (
        "expected the independent GetAppAuthorization read to confirm status stayed "
        f"PendingConnect across the update, got {fetched['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
