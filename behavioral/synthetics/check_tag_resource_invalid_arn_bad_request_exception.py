"""tag-resource-invalid-arn-bad-request-exception."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn-bad-request-exception"
GROUP = "error-semantics"
SERVICES = ["synthetics"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource refuses the malformed ResourceArn "not-an-arn" with ValidationException and its exact message,
    and tags a group the check creates by its ARN."""
    synth = ctx.client("synthetics")

    error = _client_error(lambda: synth.tag_resource(ResourceArn="not-an-arn", Tags={"k": "v"}))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    expected_message = (
        "1 validation error detected: Value 'not-an-arn' at 'resourceArn' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        r"arn:(aws[a-zA-Z-]*)?:synthetics:[a-z]{2,4}(-[a-z]{2,4})?-[a-z]+-\d{1}:\d{12}:(canary|group):[0-9a-z_\-]+"
    )
    assert error["Message"] == expected_message, f"expected message {expected_message!r}, got {error['Message']!r}"

    # Positive control: tagging a real group with a well-formed ARN succeeds.
    group_name = ctx.unique_name("sim2real-group-")
    group_arn = synth.create_group(Name=group_name)["Group"]["Arn"]
    ctx.on_cleanup(lambda: synth.delete_group(GroupIdentifier=group_name))

    synth.tag_resource(ResourceArn=group_arn, Tags={"k": "v"})
    tags = synth.list_tags_for_resource(ResourceArn=group_arn)["Tags"]
    assert tags.get("k") == "v", f"expected tag 'k'='v' after TagResource, got {tags!r}"


def _client_error(fn) -> dict:
    """Call fn() and return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
