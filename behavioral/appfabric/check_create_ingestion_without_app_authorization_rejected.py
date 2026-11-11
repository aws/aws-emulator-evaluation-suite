"""create-ingestion-without-app-authorization-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-ingestion-without-app-authorization-rejected"
GROUP = "error-semantics"
SERVICES = ["appfabric"]


def _af_client(ctx, service: str = "appfabric"):
    """AppFabric serves us-east-1, not every corpus region, so every target is called there."""
    from botocore.config import Config

    return ctx.client(
        service, region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


def _reset_appfabric(appfabric):
    """Defensively clear any pre-existing sim2real-tagged app bundle before this check runs. AppFabric enforces
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
    """CreateIngestion for an app/tenant pair that has no app authorization at all (never even
    created) is rejected -- the same underlying dependency AppFabric enforces when the
    authorization exists but isn't Connected, just triggered from a different starting state."""
    appfabric = _af_client(ctx)
    _reset_appfabric(appfabric)

    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()), tags=[{"key": "sim2real", "value": CHECK}]
    )["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    tenant_id = ctx.unique_name("sim2real-tenant-")

    from botocore.exceptions import ClientError

    try:
        appfabric.create_ingestion(
            appBundleIdentifier=bundle_arn,
            app="SLACK",
            tenantId=tenant_id,
            ingestionType="auditLog",
        )
        raise AssertionError("expected a rejection, but CreateIngestion succeeded with no app authorization")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"]["Message"]
        assert code == "ValidationException", f"expected ValidationException, got {code!r}: {err.response['Error'].get('Message')}"
        assert message == "The app authorization for the specified application and tenant was not found. Create an app authorization for the application and tenant before creating an ingestion.", (
            f"expected the exact ValidationException message AWS returns, got {message!r}"
        )

    # Effect absent: no ingestion exists for this bundle.
    listed = appfabric.list_ingestions(appBundleIdentifier=bundle_arn).get("ingestions", [])
    assert listed == [], f"expected no ingestions for a bundle with no app authorization, got {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

