"""tag-resource-invalid-tag-key-format-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-invalid-tag-key-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key over the documented 128-character limit and never attaches it;
    a well-formed tag key/value pair is accepted normally.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_Tag.html"""
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-sm-")
    created = sm.create_secret(Name=name, SecretString="value")
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    invalid_key = "k" * 200  # exceeds the documented 128-character maximum
    code, message = _error_code(
        lambda: sm.tag_resource(SecretId=arn, Tags=[{"Key": invalid_key, "Value": "x"}])
    )
    assert code == "ValidationException", f"unexpected code {code!r}"
    # The service echoes only the first 64 characters of the rejected value.
    expected_message = (
        f"1 validation error detected: Value '{invalid_key[:64]} ...' at 'tags.1.member.key' "
        "failed to satisfy constraint: Member must have length less than or equal to 128"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the invalid (oversized) tag key was never attached.
    described = sm.describe_secret(SecretId=arn)
    tag_keys = {t["Key"] for t in described.get("Tags", [])}
    assert invalid_key not in tag_keys, f"oversized key was attached anyway: {tag_keys!r}"

    # Positive control: a well-formed tag key/value within limits succeeds.
    sm.tag_resource(SecretId=arn, Tags=[{"Key": "environment.test-01", "Value": "prod"}])
    described_after = sm.describe_secret(SecretId=arn)
    tags_after = {t["Key"]: t["Value"] for t in described_after.get("Tags", [])}
    assert tags_after.get("environment.test-01") == "prod", (
        f"expected environment.test-01=prod, got {tags_after.get('environment.test-01')!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

