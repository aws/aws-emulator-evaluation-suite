"""create-app-bundle-with-customer-managed-key."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-app-bundle-with-customer-managed-key"
GROUP = "lifecycle"
SERVICES = ["appfabric"]


def _af_client(ctx, service: str = "appfabric"):
    """A client pinned to us-east-1, an AppFabric region (ctx.region need not be one); every
    resource this check creates lives in that one region."""
    from botocore.config import Config

    return ctx.client(
        service, region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _error(fn):
    """Call fn(); return the refusal's (code, message). A success raises: a target that accepts
    what AWS refuses must fail here, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAppBundle with a customerManagedKeyIdentifier persists that key's ARN on the bundle."""
    kms = _af_client(ctx, "kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-appfabric-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "appfabric-create-app-bundle-with-customer-managed-key"}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    appfabric = _af_client(ctx)
    from botocore.exceptions import ClientError as _CE
    try:
        for b in appfabric.list_app_bundles(maxResults=100).get("appBundleSummaryList", []):
            try:
                appfabric.delete_app_bundle(appBundleIdentifier=b["arn"])
            except _CE:
                pass
    except _CE:
        pass

    created = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()),
        customerManagedKeyIdentifier=key_arn,
        tags=[{"key": "sim2real", "value": "appfabric-create-app-bundle-with-customer-managed-key"}],
    )["appBundle"]
    bundle_arn = created["arn"]

    def _cleanup_bundle():
        try:
            appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn)
        except _CE:
            pass

    ctx.on_cleanup(_cleanup_bundle)

    assert created["customerManagedKeyArn"] == key_arn, (
        f"expected customerManagedKeyArn {key_arn!r} on CreateAppBundle response, "
        f"got {created.get('customerManagedKeyArn')!r}"
    )

    fetched = appfabric.get_app_bundle(appBundleIdentifier=bundle_arn)["appBundle"]
    assert fetched["customerManagedKeyArn"] == key_arn, (
        f"expected customerManagedKeyArn {key_arn!r} on an independent GetAppBundle read, "
        f"got {fetched.get('customerManagedKeyArn')!r}"
    )

    # The delete this check already performs (via cleanup) is a free negative assertion once
    # asserted here: gone via an independent read, and a mutation on the dead id also fails.
    appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn)
    code, message = _error(lambda: appfabric.get_app_bundle(appBundleIdentifier=bundle_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetAppBundle after delete, got {code!r}"
    )
    assert message == "The app bundle ID was not found.", (
        f"expected message 'The app bundle ID was not found.', got {message!r}"
    )
    code_on_dead_mutation, dead_message = _error(
        lambda: appfabric.create_app_authorization(
            appBundleIdentifier=bundle_arn,
            app="SLACK",
            authType="oauth2",
            credential={
                "oauth2Credential": {
                    "clientId": "placeholder-client-id",
                    "clientSecret": "placeholder-client-secret",
                }
            },
            tenant={
                "tenantIdentifier": ctx.unique_name("sim2real-tenant-"),
                "tenantDisplayName": "sim2real behavioral tenant",
            },
        )
    )
    assert code_on_dead_mutation == "ResourceNotFoundException", (
        f"expected a mutation against the deleted bundle to fail with ResourceNotFoundException, "
        f"got {code_on_dead_mutation!r}"
    )
    assert dead_message == "The specified app bundle ID is not valid", (
        f"expected message 'The specified app bundle ID is not valid', got {dead_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
