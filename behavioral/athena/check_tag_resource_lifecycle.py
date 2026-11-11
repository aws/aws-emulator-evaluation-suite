"""tag-resource-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = 'tags'
SERVICES = ['athena']


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource / ListTagsForResource / UntagResource round-trip tags on a WorkGroup ARN."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-tags-")
    athena.create_work_group(Name=wg)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    # Athena refuses an ARN whose account does not match the caller's, so the ARN must
    # be built from the identity the athena client itself signs with.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg}"

    athena.tag_resource(ResourceARN=arn, Tags=[{"Key": "env", "Value": "fidelity"}])
    tags = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags.get("env") == "fidelity", "tag missing immediately after TagResource"

    # Re-tagging the same key overwrites rather than duplicating.
    athena.tag_resource(ResourceARN=arn, Tags=[{"Key": "env", "Value": "fidelity2"}])
    tag_list = athena.list_tags_for_resource(ResourceARN=arn)["Tags"]
    env_entries = [t for t in tag_list if t["Key"] == "env"]
    assert len(env_entries) == 1, f"re-tagging a key must overwrite, got {len(env_entries)} 'env' entries"
    assert env_entries[0]["Value"] == "fidelity2", "re-tagging did not overwrite the value"

    athena.untag_resource(ResourceARN=arn, TagKeys=["env"])
    tags = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert "env" not in tags, "tag still present after UntagResource"

    # Untagging an absent key is a tolerated no-op: the call succeeds.
    athena.untag_resource(ResourceARN=arn, TagKeys=["env"])

    # A resource ARN from another account must be refused outright.
    foreign = f"arn:aws:athena:{ctx.region}:111122223333:workgroup/{wg}"
    mismatch = ("InvalidRequestException", "Resource ARN account does not match caller account")
    err = _error(
        lambda: athena.tag_resource(ResourceARN=foreign, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert err == mismatch, f"expected {mismatch} tagging a cross-account ARN, got {err}"

    # The refusal is not just TagResource's own opinion: an independent read of the
    # same foreign ARN must refuse identically rather than quietly reporting "no tags".
    err = _error(lambda: athena.list_tags_for_resource(ResourceARN=foreign))
    assert err == mismatch, f"expected {mismatch} reading a cross-account ARN's tags, got {err}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
