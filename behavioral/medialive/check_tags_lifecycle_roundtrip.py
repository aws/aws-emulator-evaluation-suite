"""tags-lifecycle-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tags-lifecycle-roundtrip"
GROUP = "resource-lifecycle"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags/ListTagsForResource/DeleteTags round-trip on a real MediaLive resource ARN."""
    medialive = ctx.client("medialive")
    group = medialive.create_input_security_group(WhitelistRules=[{"Cidr": "203.0.113.0/24"}])["SecurityGroup"]
    group_id = group["Id"]
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: medialive.delete_input_security_group(InputSecurityGroupId=group_id)))

    medialive.create_tags(ResourceArn=arn, Tags={"sim2real-env": "test", "sim2real-owner": "behavioral"})
    tags = medialive.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("sim2real-env") == "test"
    assert tags.get("sim2real-owner") == "behavioral"

    medialive.delete_tags(ResourceArn=arn, TagKeys=["sim2real-owner"])
    tags_after_delete = medialive.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "sim2real-owner" not in tags_after_delete
    assert tags_after_delete.get("sim2real-env") == "test"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
