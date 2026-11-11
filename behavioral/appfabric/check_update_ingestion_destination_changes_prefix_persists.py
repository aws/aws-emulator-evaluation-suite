"""update-ingestion-destination-changes-prefix-persists."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-ingestion-destination-changes-prefix-persists"
GROUP = "error-semantics"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIngestionDestination against a nonexistent ingestion destination in a real app bundle raises
    ResourceNotFoundException."""
    from botocore.exceptions import ClientError

    appfabric = _af_client(ctx, "appfabric")
    _reset_appfabric(appfabric)

    bundle_arn = appfabric.create_app_bundle(
        clientToken=str(uuid.uuid4()),
        tags=[{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behavioral"}],
    )["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    bogus_ingestion_id = str(uuid.uuid4())
    bogus_destination_id = str(uuid.uuid4())
    try:
        appfabric.get_ingestion_destination(
            appBundleIdentifier=bundle_arn,
            ingestionIdentifier=bogus_ingestion_id,
            ingestionDestinationIdentifier=bogus_destination_id,
        )
        raise AssertionError("expected ResourceNotFoundException, got a successful response")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for a nonexistent ingestion destination, got {code}"
        )
        message = err.response["Error"].get("Message")
        assert message == "The specified ingestion destination does not exist", (
            f"expected AWS's exact not-found message for the ingestion destination, got {message!r}"
        )

    # Positive control: the bundle itself is untouched by the rejected call.
    fetched_bundle = appfabric.get_app_bundle(appBundleIdentifier=bundle_arn)["appBundle"]
    assert fetched_bundle["arn"] == bundle_arn, (
        f"expected the untouched bundle {bundle_arn!r}, got {fetched_bundle['arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

