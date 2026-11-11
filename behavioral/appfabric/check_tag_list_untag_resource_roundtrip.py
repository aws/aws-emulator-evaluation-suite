"""tag-list-untag-resource-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "tag-list-untag-resource-roundtrip"
GROUP = "lifecycle"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on an app bundle."""
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

    bundle_arn = appfabric.create_app_bundle(clientToken=str(uuid.uuid4()))["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    appfabric.tag_resource(
        resourceArn=bundle_arn,
        tags=[{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behavioral"}],
    )
    tag_map = {t["key"]: t["value"] for t in appfabric.list_tags_for_resource(resourceArn=bundle_arn)["tags"]}
    assert tag_map == {"env": "sim2real", "owner": "behavioral"}, (
        f"expected tags {{'env': 'sim2real', 'owner': 'behavioral'}} after TagResource, got {tag_map}"
    )

    appfabric.untag_resource(resourceArn=bundle_arn, tagKeys=["owner"])
    tags_after = {t["key"]: t["value"] for t in appfabric.list_tags_for_resource(resourceArn=bundle_arn)["tags"]}
    assert tags_after == {"env": "sim2real"}, (
        f"expected only {{'env': 'sim2real'}} to remain after UntagResource(['owner']), got {tags_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
