"""delete-ingestion-unknown-identifier-is-noop."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-ingestion-unknown-identifier-is-noop"
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
    """Defensively clear an app bundle an earlier interrupted run left before this check runs.

    AppFabric enforces a hard, non-adjustable quota of ONE app bundle per account/region, so an
    orphaned bundle would block every check that follows it -- clear the decks first.
    """
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
                continue  # not a sim2real-tagged bundle: leave it
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
    """DeleteIngestion with a nonexistent ingestion id in a real app bundle succeeds without error
    rather than raising ResourceNotFoundException.
    """
    appfabric = _af_client(ctx)
    _reset_appfabric(appfabric)

    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()), tags=[{"key": "sim2real", "value": CHECK}]
    )["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    bogus_ingestion_id = str(uuid.uuid4())
    appfabric.delete_ingestion(appBundleIdentifier=bundle_arn, ingestionIdentifier=bogus_ingestion_id)

    # Repeat: idempotence means the second no-op call must be indistinguishable from the first,
    # not a fluke of a single call.
    appfabric.delete_ingestion(appBundleIdentifier=bundle_arn, ingestionIdentifier=bogus_ingestion_id)

    # Positive control: the bundle itself is untouched and still reachable.
    fetched_bundle = appfabric.get_app_bundle(appBundleIdentifier=bundle_arn)["appBundle"]
    assert fetched_bundle["arn"] == bundle_arn, (
        f"expected the app bundle to remain reachable at {bundle_arn!r}, "
        f"got {fetched_bundle['arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

