"""tag-resource-lifecycle-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle-roundtrip"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource; UntagResource removes them."""
    # identity-chime has no us-west-2 endpoint (botocore endpoints.json: us-east-1/eu-central-1
    # only), so the region is pinned for both targets via ctx.client's override.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"), Metadata="", ClientRequestToken=uuid.uuid4().hex
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=arn))

    client.tag_resource(ResourceARN=arn, Tags=[{"Key": "sim2real-env", "Value": "behavioral"}])

    tags = client.list_tags_for_resource(ResourceARN=arn)["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert tag_map.get("sim2real-env") == "behavioral", (
        f"expected tag sim2real-env=behavioral after TagResource, got {tag_map}"
    )

    client.untag_resource(ResourceARN=arn, TagKeys=["sim2real-env"])

    tags_after = client.list_tags_for_resource(ResourceARN=arn)["Tags"]
    keys_after = {t["Key"] for t in tags_after}
    assert "sim2real-env" not in keys_after, (
        f"expected sim2real-env removed after UntagResource, still present in {keys_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
