"""app-authorization-initial-status-pending-connect."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "app-authorization-initial-status-pending-connect"
GROUP = "state"
SERVICES = ["appfabric"]


def _af_client(ctx, service: str):
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
    """A newly created app authorization always starts in PendingConnect, prior to any connect attempt."""
    appfabric = _af_client(ctx, "appfabric")
    _reset_appfabric(appfabric)
    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()), tags=[{"key": "sim2real", "value": CHECK}]
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
        tenant={"tenantIdentifier": tenant_id, "tenantDisplayName": "sim2real behavioral tenant"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["appAuthorization"]
    auth_arn = created["appAuthorizationArn"]
    ctx.on_cleanup(
        lambda: appfabric.delete_app_authorization(
            appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
        )
    )

    assert created["status"] == "PendingConnect", f"expected PendingConnect on create, got {created['status']!r}"
    assert created["app"] == "SLACK", f"expected app SLACK, got {created['app']!r}"
    assert created["tenant"]["tenantIdentifier"] == tenant_id, (
        f"expected tenantIdentifier {tenant_id!r}, got {created['tenant']['tenantIdentifier']!r}"
    )

    fetched = appfabric.get_app_authorization(
        appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
    )["appAuthorization"]
    assert fetched["status"] == "PendingConnect", (
        f"expected PendingConnect on independent get_app_authorization read, got {fetched['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

