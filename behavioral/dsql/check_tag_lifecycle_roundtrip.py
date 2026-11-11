"""tag-lifecycle-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "tag-lifecycle-roundtrip"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource, and UntagResource removes
    exactly the requested key while leaving the others intact."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(deletionProtectionEnabled=False)
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))

    dsql.tag_resource(resourceArn=arn, tags={"sim2real-env": "behavioral", "sim2real-owner": "dsql-suite"})
    tags = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-env") == "behavioral", f"expected sim2real-env=behavioral, got {tags.get('sim2real-env')!r}"
    assert tags.get("sim2real-owner") == "dsql-suite", f"expected sim2real-owner=dsql-suite, got {tags.get('sim2real-owner')!r}"

    dsql.untag_resource(resourceArn=arn, tagKeys=["sim2real-owner"])
    tags_after = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-owner" not in tags_after, "UntagResource must remove exactly the requested key"
    assert tags_after.get("sim2real-env") == "behavioral", "untouched tag must remain"


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
