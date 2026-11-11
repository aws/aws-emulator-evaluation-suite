"""tag-resource-list-tags-untag-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-untag-roundtrip"
GROUP = "control-plane"
SERVICES = ["entityresolution"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource; UntagResource removes exactly
    the named keys and leaves the rest."""
    er = ctx.client("entityresolution")
    name = ctx.unique_name("sim2real-er-schema-")
    created = er.create_schema_mapping(
        schemaName=name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        ],
        tags={"env": "sim2real"},
    )
    arn = created["schemaArn"]
    ctx.on_cleanup(lambda: _safe_delete(er, name))

    tags = er.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("env") == "sim2real", f"expected tags to include env=sim2real, got {tags}"

    er.tag_resource(resourceArn=arn, tags={"owner": "sim2real-suite"})
    tags = er.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"env": "sim2real", "owner": "sim2real-suite"}, (
        f"expected tags {{'env': 'sim2real', 'owner': 'sim2real-suite'}} after TagResource, got {tags}"
    )

    er.untag_resource(resourceArn=arn, tagKeys=["owner"])
    tags = er.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"env": "sim2real"}, (
        f"expected only env=sim2real to remain after UntagResource(owner), got {tags}"
    )


def _safe_delete(er, name):
    try:
        er.delete_schema_mapping(schemaName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
