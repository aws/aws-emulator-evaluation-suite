"""untag-resource-nonexistent-tag-is-noop."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-tag-is-noop"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource for a key the resource never had succeeds and leaves its tags unchanged, untagging a
    present key removes it, and UntagResource on a nonexistent bucket ARN is NotFoundException "The
    specified bucket does not exist." without touching the real bucket's tags."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_bucket(ctx, "untagblk")
    s3t.tag_resource(resourceArn=bucket_arn, tags={"sim2real-marker": "present"})

    baseline = s3t.list_tags_for_resource(resourceArn=bucket_arn)["tags"]

    # Real AWS treats removal of an absent tag key as an idempotent no-op: it must NOT
    # raise, and it must NOT touch unrelated keys.
    s3t.untag_resource(resourceArn=bucket_arn, tagKeys=["sim2real-never-applied"])

    after = s3t.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert after == baseline, "no-op untag of an absent key must leave existing tags unchanged"

    # Positive control: removing a tag key that IS present succeeds.
    s3t.untag_resource(resourceArn=bucket_arn, tagKeys=["sim2real-marker"])
    final = s3t.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert "sim2real-marker" not in final, f"expected sim2real-marker removed, got tags: {final}"

    # Overly-permissive guard: UntagResource on a resource ARN that does not exist at all
    # (as opposed to an absent tag key on a real resource) IS rejected.
    fake_arn = bucket_arn + "-does-not-exist"
    code, message = _error(lambda: s3t.untag_resource(resourceArn=fake_arn, tagKeys=["sim2real-marker"]))
    assert code == "NotFoundException", f"unexpected code: {code}"
    assert message == "The specified bucket does not exist.", message

    # Independent read at the destination: the rejected call on the nonexistent ARN must
    # not have perturbed the real bucket's tag state.
    after_guard = s3t.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert after_guard == final, f"rejected UntagResource on unrelated ARN mutated real tags: {after_guard}"


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
