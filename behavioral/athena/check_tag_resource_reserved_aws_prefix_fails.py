"""tag-resource-reserved-aws-prefix-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-fails"
GROUP = 'overly-permissive'
SERVICES = ['athena']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Tagging with a reserved 'aws:' key prefix must be rejected, not silently accepted."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(Name=name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    account = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:athena:{ctx.region}:{account}:workgroup/{name}"

    # positive control: an ordinary tag key must be accepted, so the rejection below
    # proves the reserved prefix is special-cased rather than TagResource being broken
    # for every call.
    athena.tag_resource(ResourceARN=arn, Tags=[{"Key": "env", "Value": "behavioral-check"}])
    tags_after_control = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags_after_control.get("env") == "behavioral-check", (
        f"expected positive control tag to be applied, got {tags_after_control}"
    )

    expected = (
        "InvalidRequestException",
        "System Tags (such as those with the prefix 'aws:') are not allowed to be modified.",
    )
    try:
        result = athena.tag_resource(ResourceARN=arn, Tags=[{"Key": "aws:reserved", "Value": "nope"}])
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"expected the reserved 'aws:' key to be refused, but TagResource returned {result!r}")
    assert err == expected, f"expected {expected}, got {err}"

    # no tag should have leaked through from the rejected call, and the earlier
    # control tag must still be intact
    tags = {t["Key"]: t["Value"] for t in athena.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert "aws:reserved" not in tags, f"expected no 'aws:reserved' tag, got keys {list(tags)}"
    assert tags.get("env") == "behavioral-check", (
        f"expected control tag to survive the rejected call, got {tags}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
