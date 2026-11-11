"""tag-resource-malformed-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-malformed-key-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a key outside the allowed character set (letters, digits, whitespace, _.:/=+@-) is
    BadRequestException with the exact message and applies no tag, while a well-formed tag on the same
    resource is applied."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_bucket(ctx, "tagrej")

    code, message = _error(
        lambda: s3t.tag_resource(resourceArn=bucket_arn, tags={"bad key!": "value"})
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        "The provided tags are invalid. Tag key can only contain alphanumeric characters, "
        "spaces, and _.:/=+@-"
    ), message

    # Effect absent: the malformed tag never landed on the resource.
    tags_after = s3t.list_tags_for_resource(resourceArn=bucket_arn).get("tags", {})
    assert "bad key!" not in tags_after, (
        f"malformed tag key was applied despite rejection: {tags_after}"
    )

    # Positive control: a well-formed tag key/value is accepted.
    s3t.tag_resource(resourceArn=bucket_arn, tags={"sim2real-owner": "team"})
    tags_after2 = s3t.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert tags_after2.get("sim2real-owner") == "team", (
        f"expected well-formed tag to be applied, got {tags_after2}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn() expecting a refusal; return (code, message). An unexpected
    success raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, suffix: str) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
