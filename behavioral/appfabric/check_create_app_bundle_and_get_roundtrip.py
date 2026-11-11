"""create-app-bundle-and-get-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-app-bundle-and-get-roundtrip"
GROUP = "lifecycle"
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
    """AppFabric enforces a hard, non-adjustable quota of ONE app bundle per account/region, so a
    bundle orphaned by an earlier interrupted run -- possibly still holding an app authorization or
    ingestion that blocks DeleteAppBundle -- would block this check from ever creating its own.
    Clear the decks first, tearing down each bundle's contents before the bundle itself."""
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAppBundle returns an ARN that GetAppBundle echoes back consistently. Once
    DeleteAppBundle removes the bundle, an independent read observes it gone, and a second
    DeleteAppBundle on the same dead id is idempotent rather than erroring."""
    appfabric = _af_client(ctx)
    _reset_appfabric(appfabric)

    created = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()), tags=[{"key": "sim2real", "value": CHECK}]
    )["appBundle"]
    bundle_arn = created["arn"]

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # A freshly created app bundle with no customerManagedKeyIdentifier uses an
    # AWS owned key, so no customer-managed key ARN should be reported.
    cmk_arn = created.get("customerManagedKeyArn")
    assert cmk_arn in (None, ""), f"expected no customerManagedKeyArn, got {cmk_arn!r}"

    fetched = appfabric.get_app_bundle(appBundleIdentifier=bundle_arn)["appBundle"]
    assert fetched["arn"] == bundle_arn, f"expected arn {bundle_arn!r}, got {fetched['arn']!r}"

    appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn)

    read_code, read_message = _error(lambda: appfabric.get_app_bundle(appBundleIdentifier=bundle_arn))
    assert read_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on read after delete, got {read_code!r}"
    )
    assert read_message == "The app bundle ID was not found.", (
        f"expected message 'The app bundle ID was not found.', got {read_message!r}"
    )

    # Real AWS's DeleteAppBundle is idempotent for an already-deleted bundle: a second
    # delete of the same dead id succeeds rather than raising ResourceNotFoundException.
    appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
