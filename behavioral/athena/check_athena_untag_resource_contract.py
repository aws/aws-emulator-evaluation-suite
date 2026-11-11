"""athena-untag-resource-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-untag-resource-contract"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested tag keys and leaves the rest intact;
    calling it against a workgroup ARN that does not exist is rejected with
    ResourceNotFoundException and mutates nothing."""
    athena = ctx.client("athena")
    account_id = _account_id(ctx)

    wg_name = ctx.unique_name("sim2real-athena-wg-")
    athena.create_work_group(
        Name=wg_name,
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "sim2real"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    resource_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg_name}"

    before = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=resource_arn)["Tags"]}
    assert before == {"env": "test", "owner": "sim2real"}, before

    # success path: untag exactly one key, the other must survive untouched
    athena.untag_resource(ResourceARN=resource_arn, TagKeys=["env"])
    after = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=resource_arn)["Tags"]}
    assert after == {"owner": "sim2real"}, f"expected only 'owner' tag to remain, got {after}"

    # error boundary: ResourceARN that was never created
    bogus_wg = ctx.unique_name("sim2real-athena-missing-wg-")
    bogus_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{bogus_wg}"
    code, message = _error(lambda: athena.untag_resource(ResourceARN=bogus_arn, TagKeys=["owner"]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Could not find valid resource from ARN: {bogus_arn}", message

    # the real resource's remaining tag must be unaffected by the failed call above
    final = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=resource_arn)["Tags"]}
    assert final == {"owner": "sim2real"}, final


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
