"""add-tags-nonexistent-parameter-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-tags-nonexistent-parameter-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTagsToResource and ListTagsForResource on a nonexistent parameter fail with
    InvalidResourceId and its exact message rather than tagging a phantom resource; the same
    AddTagsToResource on an existing parameter succeeds as a positive control."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    # Positive control: the same call shape against a parameter that exists.
    real = _param_name("probe-param-goodtag-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=real))
    ssm.put_parameter(Name=real, Value="v1", Type="String")
    ssm.add_tags_to_resource(
        ResourceType="Parameter",
        ResourceId=real,
        Tags=[{"Key": "env", "Value": "test"}],
    )
    tag_map = {
        t["Key"]: t["Value"]
        for t in ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=real)["TagList"]
    }
    assert tag_map.get("env") == "test", f"positive control did not tag {real!r}: {tag_map}"
    assert tag_map == {"env": "test"}, f"positive control tags are {tag_map!r}"

    missing = _param_name("probe-param-badtag-")

    code, message = _error_code(
        lambda: ssm.add_tags_to_resource(
            ResourceType="Parameter",
            ResourceId=missing,
            Tags=[{"Key": "env", "Value": "test"}],
        )
    )
    assert code == "InvalidResourceId", f"expected InvalidResourceId, got {code!r}"
    assert message == "", f"AddTagsToResource message: {message!r}"

    # Independent read at the destination, through a different operation than
    # the one that was rejected: the phantom resource has no tags.
    list_code, list_message = _error_code(
        lambda: ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=missing)
    )
    assert list_code == "InvalidResourceId", f"expected InvalidResourceId, got {list_code!r}"
    assert list_message == "", f"ListTagsForResource message: {list_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
