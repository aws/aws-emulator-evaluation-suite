"""tag-resource-unknown-arn-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-unknown-arn-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error_code(fn):
    """Call fn() and return its botocore (code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a well-formed but nonexistent group ARN fails with ResourceNotFoundException.
    A positive control (tag a real group, read it back) shows the refusal is specific to the ARN."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-acct-")[:32].rstrip("-")
    real_arn = xr.create_group(GroupName=name, FilterExpression='service("default")')["Group"]["GroupARN"]
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))

    xr.tag_resource(ResourceARN=real_arn, Tags=[{"Key": "k", "Value": "v"}])
    tag_map = {t["Key"]: t["Value"] for t in xr.list_tags_for_resource(ResourceARN=real_arn)["Tags"]}
    assert tag_map.get("k") == "v", f"positive control failed: TagResource then ListTagsForResource did not reflect the tag, got {tag_map}"

    account = real_arn.split(":")[4]
    bogus_arn = (
        f"arn:aws:xray:{ctx.region}:{account}:group/"
        f"{ctx.unique_name('sim2real-behav-ghost-')}/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    code, message = _error_code(
        lambda: xr.tag_resource(ResourceARN=bogus_arn, Tags=[{"Key": "k", "Value": "v"}])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Resource {bogus_arn} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
