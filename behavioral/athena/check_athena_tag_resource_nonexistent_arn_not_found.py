"""athena-tag-resource-nonexistent-arn-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-tag-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and ListTagsForResource on a well-formed ARN of a missing workgroup fail
    ResourceNotFoundException, and both succeed once the workgroup exists at that ARN."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-athena-wg-ghost-")
    bogus_arn = f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{name}"

    from botocore.exceptions import ClientError

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

    expected = f"Could not find valid resource from ARN: {bogus_arn}"
    code, message = _error(lambda: athena.tag_resource(ResourceARN=bogus_arn, Tags=[{"Key": "k", "Value": "v"}]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code2, message2 = _error(lambda: athena.list_tags_for_resource(ResourceARN=bogus_arn))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2!r}"
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"

    # Restore leg (positive control): creating the workgroup at this exact ARN
    # makes the identical calls succeed, so the rejection above tracked this
    # specific resource's absence rather than firing unconditionally.
    athena.create_work_group(Name=name)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    athena.tag_resource(ResourceARN=bogus_arn, Tags=[{"Key": "k", "Value": "v"}])
    tags_now = athena.list_tags_for_resource(ResourceARN=bogus_arn)["Tags"]
    assert {"Key": "k", "Value": "v"} in tags_now, f"expected tag to be present, got {tags_now!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
