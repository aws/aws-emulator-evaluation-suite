"""tag-resource-reserved-prefix-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-prefix-denied"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tagging a table bucket with an aws:-reserved key prefix is rejected with
    BadRequestException rather than being silently stored."""
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-tag-")
    bucket_arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=bucket_arn))

    reserved_key = "aws:reserved-marker"
    code, message = _error(
        lambda: s3t.tag_resource(resourceArn=bucket_arn, tags={reserved_key: "x"})
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Tags beginning with 'aws:' are reserved for system use.", message

    # effect absent: the reserved-prefix tag was never stored
    tags_after_reject = s3t.list_tags_for_resource(resourceArn=bucket_arn).get("tags", {})
    assert reserved_key not in tags_after_reject, (
        f"reserved tag key {reserved_key!r} present after rejection: {tags_after_reject}"
    )

    # positive control: a normal tag on the same resource is stored correctly
    s3t.tag_resource(resourceArn=bucket_arn, tags={"team": "sim2real"})
    ctx.on_cleanup(lambda: s3t.untag_resource(resourceArn=bucket_arn, tagKeys=["team"]))
    tags_after_accept = s3t.list_tags_for_resource(resourceArn=bucket_arn).get("tags", {})
    assert tags_after_accept.get("team") == "sim2real", (
        f"expected positive-control tag team=sim2real, got {tags_after_accept.get('team')!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
