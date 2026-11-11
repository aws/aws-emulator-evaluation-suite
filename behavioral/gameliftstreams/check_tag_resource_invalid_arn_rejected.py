"""tag-resource-invalid-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn-rejected"
GROUP = "validation"
SERVICES = ["gameliftstreams"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a malformed ResourceArn fails with BadRequestException 'Invalid input resource arn:
    bad syntax', while tagging a real resource succeeds and ListTagsForResource shows the tag.
    """
    gls = ctx.client("gameliftstreams")

    code, message = _error(lambda: gls.tag_resource(ResourceArn="not-an-arn", Tags={"k": "v"}))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Invalid input resource arn: bad syntax", f"unexpected message {message!r}"

    # positive control: tagging a real resource with a real ARN succeeds
    try:
        group = gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"), StreamClass="gen6n_small"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_stream_group(Identifier=arn)))

    gls.tag_resource(ResourceArn=arn, Tags={"env": "sim2real-test"})
    tags = gls.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("env") == "sim2real-test", f"expected tag env=sim2real-test, got {tags!r}"


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING an input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
