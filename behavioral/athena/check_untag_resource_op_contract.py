"""op-contract-untag-resource."""
from __future__ import annotations

CHECK = "op-contract-untag-resource"
GROUP = "error-semantics"
SERVICES = ["athena"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named tag keys; a nonexistent ARN is refused without mutating any real resource's tags."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    wg_name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=wg_name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name))
    wg_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg_name}"

    # Success path: tag with two keys, then untag one.
    athena.tag_resource(
        ResourceARN=wg_arn,
        Tags=[{"Key": "Env", "Value": "test"}, {"Key": "Owner", "Value": "sim2real"}],
    )
    tags_after_tag = {
        t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=wg_arn)["Tags"]
    }
    assert tags_after_tag == {"Env": "test", "Owner": "sim2real"}, (
        f"expected both tags after TagResource, got {tags_after_tag}"
    )

    athena.untag_resource(ResourceARN=wg_arn, TagKeys=["Owner"])
    tags_after_untag = {
        t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=wg_arn)["Tags"]
    }
    assert tags_after_untag == {"Env": "test"}, f"expected only Env tag to remain, got {tags_after_untag}"

    # Error boundary: untag against a workgroup ARN that does not exist.
    bogus_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{ctx.unique_name('sim2real-nope-')}"
    not_found = ("ResourceNotFoundException", f"Could not find valid resource from ARN: {bogus_arn}")
    err = _error(lambda: athena.untag_resource(ResourceARN=bogus_arn, TagKeys=["Env"]))
    assert err == not_found, f"expected {not_found}, got {err}"

    # The real resource's remaining tags must be unaffected by the failed call on a different ARN.
    tags_final = {
        t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=wg_arn)["Tags"]
    }
    assert tags_final == {"Env": "test"}, (
        f"real workgroup's tags must be unaffected by the failed call on a different ARN, got {tags_final}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
