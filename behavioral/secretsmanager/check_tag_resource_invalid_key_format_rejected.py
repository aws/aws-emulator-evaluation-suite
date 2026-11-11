"""tag-resource-invalid-key-format-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-format-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a reserved aws:-prefixed tag key is rejected instead of being silently applied."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secmgr-badtag-")
    created = sm.create_secret(Name=name, SecretString="tag-guard-value")
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    code, message = _error_code(
        lambda: sm.tag_resource(SecretId=secret_arn, Tags=[{"Key": "aws:reserved-key", "Value": "nope"}])
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "You can't modify system tags. Tag key: 'aws:reserved-key'.", (
        f"unexpected reserved-key message: {message!r}"
    )

    # Effect absent: the reserved tag was not applied.
    after = sm.describe_secret(SecretId=secret_arn)
    tag_keys = {t["Key"] for t in after.get("Tags", [])}
    assert "aws:reserved-key" not in tag_keys, f"reserved tag key leaked into {tag_keys!r}"

    # Positive control: a normal tag key on the same secret is accepted. DescribeSecret can
    # briefly lag behind a just-applied TagResource, so poll to a bounded deadline.
    sm.tag_resource(SecretId=secret_arn, Tags=[{"Key": "team", "Value": "platform"}])
    control_tags = _poll_for_tag(sm, secret_arn, "team", "platform", timeout_s=30.0)
    assert control_tags.get("team") == "platform", (
        f"positive control tag never observed via DescribeSecret; last saw {control_tags!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll_for_tag(sm, secret_arn: str, key: str, expected_value: str, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last_tags: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_secret(SecretId=secret_arn)
        last_tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
        if last_tags.get(key) == expected_value:
            return last_tags
        time.sleep(2)
    raise AssertionError(
        f"tag {key}={expected_value!r} not observed via DescribeSecret within {timeout_s}s; "
        f"last saw {last_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
