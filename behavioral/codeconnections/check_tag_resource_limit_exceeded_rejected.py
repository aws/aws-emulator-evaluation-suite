"""tag-resource-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeconnections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 51st tag on a connection is refused with LimitExceededException and the 50 tags stay, while
    overwriting an existing key succeeds; after one untag the rejected tag is added."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2realcc-")[-32:]
    conn_arn = cc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=conn_arn))

    # fill up to the real cap of 50 tags in a single call
    full_tags = [{"Key": f"sim2real-tag-{i}", "Value": "v"} for i in range(50)]
    cc.tag_resource(ResourceArn=conn_arn, Tags=full_tags)
    assert len(cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]) == 50

    # adding one more, brand-new key pushes the resource past the real limit -> rejected
    from botocore.exceptions import ClientError

    try:
        cc.tag_resource(ResourceArn=conn_arn, Tags=[{"Key": "sim2real-tag-50", "Value": "v"}])
        raise AssertionError("expected LimitExceededException but call succeeded")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        msg = err.response["Error"].get("Message", "")
        assert code == "LimitExceededException", "actual_code=" + code + " msg=" + msg[:200]
        assert msg == "The resultant tag set must not have more than 50 user tags.", "msg=" + repr(msg)

    tags_after = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]}
    assert "sim2real-tag-50" not in tags_after
    assert len(tags_after) == 50

    # positive control: overwriting an existing key (no growth in tag count) still succeeds
    cc.tag_resource(ResourceArn=conn_arn, Tags=[{"Key": "sim2real-tag-0", "Value": "updated"}])
    tags_final = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]}
    assert tags_final["sim2real-tag-0"] == "updated"
    assert len(tags_final) == 50

    # restore: freeing one slot lifts the cap -- the identical add rejected above now succeeds
    cc.untag_resource(ResourceArn=conn_arn, TagKeys=["sim2real-tag-49"])
    tags_freed = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]}
    assert len(tags_freed) == 49, "actual_count=" + str(len(tags_freed))

    cc.tag_resource(ResourceArn=conn_arn, Tags=[{"Key": "sim2real-tag-50", "Value": "v"}])
    tags_restored = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=conn_arn)["Tags"]}
    assert tags_restored.get("sim2real-tag-50") == "v", "actual_tags=" + repr(sorted(tags_restored))
    assert len(tags_restored) == 50, "actual_count=" + str(len(tags_restored))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
