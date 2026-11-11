"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested keys from a workgroup and rejects an unknown ARN."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")

    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(Name=wg_name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name))

    account_id = sts.get_caller_identity()["Account"]
    arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg_name}"

    # success path: tag with two keys, then untag one and assert exactly the other survives.
    athena.tag_resource(ResourceARN=arn, Tags=[
        {"Key": "keep-me", "Value": "1"},
        {"Key": "drop-me", "Value": "2"},
    ])
    before = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert before == {"keep-me": "1", "drop-me": "2"}, f"expected both tags after TagResource, got {before}"

    athena.untag_resource(ResourceARN=arn, TagKeys=["drop-me"])
    after = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert after == {"keep-me": "1"}, f"expected only 'keep-me' to remain after UntagResource, got {after}"

    # error boundary: untagging a resource ARN that does not exist is rejected.
    bogus_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{ctx.unique_name('sim2real-athena-nope-')}"
    not_found = ("ResourceNotFoundException", f"Could not find valid resource from ARN: {bogus_arn}")
    err = _error(lambda: athena.untag_resource(ResourceARN=bogus_arn, TagKeys=["keep-me"]))
    assert err == not_found, f"expected {not_found}, got {err}"

    # positive control: original resource is unaffected by the failed call above.
    still_there = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert still_there == {"keep-me": "1"}, f"expected 'keep-me' unaffected by the failed call, got {still_there}"


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected UntagResource on a nonexistent ARN to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
