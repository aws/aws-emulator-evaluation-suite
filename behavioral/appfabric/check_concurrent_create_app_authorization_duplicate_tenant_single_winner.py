"""concurrent-create-app-authorization-duplicate-tenant-single-winner."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-app-authorization-duplicate-tenant-single-winner"
GROUP = "concurrency"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers creating an app authorization for the same app/tenant: exactly one wins, the rest conflict."""
    from botocore.exceptions import ClientError

    appfabric = _af_client(ctx, "appfabric")
    _reset_appfabric(appfabric)
    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()), tags=[{"key": "sim2real", "value": CHECK}]
    )["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    tenant_id = ctx.unique_name("sim2real-tenant-")
    racer_count = 5

    def _race(_i):
        try:
            resp = appfabric.create_app_authorization(
                appBundleIdentifier=bundle_arn,
                app="SLACK",
                authType="oauth2",
                credential={
                    "oauth2Credential": {
                        "clientId": "placeholder-client-id",
                        "clientSecret": "placeholder-client-secret",
                    }
                },
                tenant={"tenantIdentifier": tenant_id, "tenantDisplayName": "race-tenant"},
            )
            return ("ok", resp["appAuthorization"]["appAuthorizationArn"])
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"]["Message"]))


    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_race, range(racer_count)))

    winners = [arn for status, arn in results if status == "ok"]
    losers = [error for status, error in results if status == "error"]

    assert len(winners) == 1, f"expected exactly one winner, got {winners}"
    assert len(losers) == racer_count - 1, f"expected {racer_count - 1} losers, got {results}"
    # AppFabric's tie-break for the losers isn't guaranteed to be a single error code: some
    # racers lose to the dedup check (ConflictException), while others can lose to a validation
    # pass that runs concurrently with -- and sees stale state relative to -- the winner's insert
    # (ValidationException). Either way, at most one racer may ever succeed.
    refusals = {
        "ConflictException": (
            f"Request to create AppAuthorization for App SLACK with authType oauth2 and "
            f"tenantIdentifier {tenant_id} is already in progress."
        ),
        "ValidationException": "ClientId is already being used for this AppBundle and App.",
    }
    for code, message in losers:
        assert code in refusals, losers
        assert message == refusals[code], losers


    winner_arn = winners[0]
    ctx.on_cleanup(
        lambda: appfabric.delete_app_authorization(
            appBundleIdentifier=bundle_arn, appAuthorizationIdentifier=winner_arn
        )
    )

    listed = appfabric.list_app_authorizations(appBundleIdentifier=bundle_arn)["appAuthorizationSummaryList"]
    assert len(listed) == 1, f"expected the fresh bundle to hold exactly one authorization total, found: {listed}"
    matching = [a for a in listed if a["tenant"]["tenantIdentifier"] == tenant_id]
    assert len(matching) == 1, f"expected exactly one persisted authorization for tenant {tenant_id}, found: {listed}"
    assert matching[0]["appAuthorizationArn"] == winner_arn, (
        f"persisted authorization {matching[0]['appAuthorizationArn']} does not match winner {winner_arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
