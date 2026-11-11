"""get-app-authorization-nonexistent-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-app-authorization-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["appfabric"]


def _error(fn):
    """Call fn(); return the refusal's (code, message). A success raises: a target that accepts
    what AWS refuses must fail here, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAppAuthorization on a bogus identifier in a real app bundle raises ResourceNotFoundException."""
    appfabric = _af_client(ctx)
    _reset_appfabric(appfabric)

    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()), tags=[{"key": "sim2real", "value": CHECK}]
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
        tags=[{"key": "sim2real", "value": CHECK}],
    )["appAuthorization"]["appAuthorizationArn"]

    ctx.on_cleanup(
        lambda: appfabric.delete_app_authorization(
            appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
        )
    )

    bogus_id = str(uuid.uuid4())
    code, message = _error(
        lambda: appfabric.get_app_authorization(
            appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=bogus_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a bogus appAuthorizationIdentifier, got {code!r}"
    )
    assert message == "The app authorization was not found.", (
        f"expected message 'The app authorization was not found.', got {message!r}"
    )

    # Positive control: the real app authorization in the same bundle is still gettable.
    fetched = appfabric.get_app_authorization(
        appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
    )["appAuthorization"]
    assert fetched["appAuthorizationArn"] == auth_arn, (
        f"expected GetAppAuthorization to still return {auth_arn!r} for the real authorization, "
        f"got {fetched['appAuthorizationArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
