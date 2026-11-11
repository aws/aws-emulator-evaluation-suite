"""tag-resource-invalid-key-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a reserved 'aws:' tag key prefix is rejected with
    BadRequestException rather than silently applied, the reserved key never
    lands on the resource, and a normal tag key is applied successfully."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    code, message = _error(
        lambda: s3tables.tag_resource(
            resourceArn=bucket_arn, tags={"aws:sim2real-reserved": "nope"}
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Tags beginning with 'aws:' are reserved for system use.", message

    tags_after_reject = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert "aws:sim2real-reserved" not in tags_after_reject, (
        f"reserved tag key was applied despite rejection: {tags_after_reject}"
    )

    # Positive control: a normal tag key/value is applied and retrievable.
    s3tables.tag_resource(resourceArn=bucket_arn, tags={"sim2real-Environment": "test"})
    tags_after_valid = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert tags_after_valid.get("sim2real-Environment") == "test", (
        f"expected sim2real-Environment=test after valid TagResource, got {tags_after_valid}"
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


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
