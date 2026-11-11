"""tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-and-list-tags-round-trip"
GROUP = "control-plane"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a signing profile ARN."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "tags")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))

    arn = signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)["arn"]

    initial_tags = signer.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-env" not in initial_tags, (
        f"expected no sim2real-env tag on a freshly created profile, got {initial_tags}"
    )

    signer.tag_resource(resourceArn=arn, tags={"sim2real-env": "behavioral"})
    tags = signer.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-env") == "behavioral", (
        f"expected sim2real-env=behavioral after tag_resource, got {tags}"
    )

    signer.untag_resource(resourceArn=arn, tagKeys=["sim2real-env"])
    tags_after = signer.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-env" not in tags_after, (
        f"expected sim2real-env removed after untag_resource, got {tags_after}"
    )


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _cancel_quietly(signer, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
