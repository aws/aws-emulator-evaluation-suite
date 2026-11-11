"""tag-resource-invalid-tag-key-format-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "tag-resource-invalid-tag-key-format-rejected"
GROUP = "negative-classes"
SERVICES = ["stepfunctions"]

_MAX_TAG_KEY_LEN = 128


def _client_error(fn):
    """The botocore Error dict `fn` raises. An unexpected SUCCESS raises AssertionError, so a
    target accepting a call real AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _raw_client(ctx, service):
    """A ctx client with local parameter (length) validation disabled, so an out-of-range tag
    key reaches the service instead of being rejected by botocore before it is sent."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a tag key that exceeds the 128-character maximum is rejected with
    a validation error distinct from TooManyTags (the count-based limit), the offending
    tag is never applied, and a well-formed tag on the same resource still succeeds."""
    sfn = ctx.client("stepfunctions")
    sfn_raw = _raw_client(ctx, "stepfunctions")

    role_arn = _create_role_for_state_machine(ctx)
    definition = json.dumps(
        {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    )
    sm_name = ctx.unique_name("sim2real-sfn-tagtest-")
    resource_arn = sfn.create_state_machine(name=sm_name, definition=definition, roleArn=role_arn)[
        "stateMachineArn"
    ]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=resource_arn))

    # Tag key exceeds the documented 128-character maximum -- an out-of-range format
    # violation, distinct from the too-many-tags count limit checked below.
    too_long_key = "k" * (_MAX_TAG_KEY_LEN + 1)
    error_too_long = _client_error(
        lambda: sfn_raw.tag_resource(
            resourceArn=resource_arn, tags=[{"key": too_long_key, "value": "x"}]
        )
    )
    code_too_long = error_too_long.get("Code")
    assert code_too_long == "ValidationException", error_too_long
    expected_too_long = (
        f"1 validation error detected: Value '{too_long_key}' at 'tags.1.member.key' failed to "
        f"satisfy constraint: Member must have length less than or equal to {_MAX_TAG_KEY_LEN}"
    )
    assert error_too_long.get("Message") == expected_too_long, (
        f"expected {expected_too_long!r}, got {error_too_long.get('Message')!r}"
    )

    # TooManyTags is a distinct error path: the count limit, not a per-tag format check.
    too_many_tags = [{"key": f"k{i}", "value": "v"} for i in range(60)]
    error_too_many = _client_error(
        lambda: sfn.tag_resource(resourceArn=resource_arn, tags=too_many_tags)
    )
    code_too_many = error_too_many.get("Code")
    assert code_too_many == "TooManyTags", error_too_many
    expected_too_many = "Too many tags provided."
    assert error_too_many.get("Message") == expected_too_many, (
        f"expected {expected_too_many!r}, got {error_too_many.get('Message')!r}"
    )
    assert code_too_many != code_too_long, (
        f"format violation and count violation returned the same error code: {code_too_many!r}"
    )

    # Effect absent: neither the oversized key nor the bulk tags were applied.
    tags_now = sfn.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    keys_now = {t["key"] for t in tags_now}
    assert too_long_key not in keys_now, (
        f"expected oversized key absent, found it applied: {keys_now!r}"
    )
    assert "k0" not in keys_now, f"expected TooManyTags batch absent, found k0 in: {keys_now!r}"

    # Positive control: a well-formed, in-range tag is applied.
    sfn.tag_resource(resourceArn=resource_arn, tags=[{"key": "valid-key", "value": "ok"}])
    tags_now = sfn.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    applied = {t["key"]: t["value"] for t in tags_now}
    assert applied.get("valid-key") == "ok", (
        f"expected well-formed tag to be applied after prior rejections, got: {applied!r}"
    )


def _create_role_for_state_machine(ctx) -> str:
    iam = ctx.client("iam")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_name = ctx.unique_name("sim2real-sfn-tagrole-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
