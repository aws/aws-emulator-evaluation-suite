"""delete-app-bundle-with-contents-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-app-bundle-with-contents-rejected"
GROUP = "overly-permissive"
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


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")



def _af_client(ctx, service: str = "appfabric"):
    """A client pinned to us-east-1, an AppFabric region (ctx.region need not be one); every
    resource this check creates lives in that one region."""
    from botocore.config import Config

    return ctx.client(
        service, region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _reset_appfabric(appfabric):
    """Defensively clear an app bundle a previous run of these checks left. AppFabric enforces
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
                continue  # not a bundle these checks created: leave it
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
    """DeleteAppBundle is rejected (ValidationException) while it still contains an app
    authorization; deleting the contents first lets the same DeleteAppBundle call succeed."""
    appfabric = _af_client(ctx)
    _reset_appfabric(appfabric)

    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()),
        tags=[{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behavioral"}],
    )["appBundle"]["arn"]

    def _ignore_not_found(call):
        from botocore.exceptions import ClientError

        try:
            call()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))
    )

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
        tags=[{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behavioral"}],
    )["appAuthorization"]["appAuthorizationArn"]
    # DeleteAppBundle is refused while the authorization exists: LIFO deletes it first.
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: appfabric.delete_app_authorization(
                appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
            )
        )
    )

    # Confirm the authorization is visible via the list API before probing the delete-block --
    # DeleteAppBundle's contents-check may run against a slightly-lagged index relative to the
    # CreateAppAuthorization response we just got back.
    def _auth_visible():
        listed = appfabric.list_app_authorizations(appBundleIdentifier=bundle_arn).get(
            "appAuthorizationSummaryList", []
        )
        return any(a["appAuthorizationArn"] == auth_arn for a in listed)

    _poll_until(_auth_visible, lambda visible: visible)

    code, message = _error(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "The specified app bundle cannot be deleted.", (
        f"expected message 'The specified app bundle cannot be deleted.', got {message!r}"
    )


    # Effect absent: the bundle (and its app authorization) are still there.
    still_there = appfabric.get_app_bundle(appBundleIdentifier=bundle_arn)["appBundle"]
    assert still_there["arn"] == bundle_arn, (
        f"the rejected DeleteAppBundle must have no effect: expected GetAppBundle to still report "
        f"{bundle_arn!r}, got {still_there['arn']!r}"
    )

    # Positive control: the same DeleteAppBundle call succeeds once its contents are removed.
    appfabric.delete_app_authorization(
        appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=auth_arn
    )
    appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn)

    code_after_delete, message_after_delete = _error(
        lambda: appfabric.get_app_bundle(appBundleIdentifier=bundle_arn)
    )
    assert code_after_delete == "ResourceNotFoundException", (
        f"once the app bundle is actually empty and deleted, GetAppBundle must report "
        f"ResourceNotFoundException; got {code_after_delete!r}"
    )
    assert message_after_delete == "The app bundle ID was not found.", (
        f"expected message 'The app bundle ID was not found.', got {message_after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
