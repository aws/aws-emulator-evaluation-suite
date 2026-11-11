"""tag-resource-nonexistent-resource-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource against a workgroup ARN that was never
    created both fail with ResourceNotFoundException; no tag is ever recorded."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-wg-ghost-")
    arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{name}"

    not_found = ("ResourceNotFoundException", f"Could not find valid resource from ARN: {arn}")
    err = _error(
        lambda: athena.tag_resource(ResourceARN=arn, Tags=[{"Key": "K", "Value": "V"}])
    )
    assert err == not_found, f"expected {not_found}, got {err}"

    err2 = _error(lambda: athena.list_tags_for_resource(ResourceARN=arn))
    assert err2 == not_found, f"expected {not_found}, got {err2}"

    # Positive control: creating the workgroup first makes both calls succeed.
    athena.create_work_group(Name=name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    athena.tag_resource(ResourceARN=arn, Tags=[{"Key": "K", "Value": "V"}])
    tags_after = athena.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert {"Key": "K", "Value": "V"} in tags_after, f"expected tag K=V in {tags_after}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to raise ClientError, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
