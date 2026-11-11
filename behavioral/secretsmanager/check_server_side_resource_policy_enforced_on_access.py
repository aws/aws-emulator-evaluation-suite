"""server-side-resource-policy-enforced-on-access."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-resource-policy-enforced-on-access"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A resource policy explicitly denying a principal's GetSecretValue action is enforced
    server-side, blocking access consistent with the attached policy document -- and access is
    restored the instant the deny statement is removed."""
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]

    denied_name = ctx.unique_name("sim2real-behav-respolicydeny-")
    control_name = ctx.unique_name("sim2real-behav-respolicyctrl-")

    denied_arn = sm.create_secret(Name=denied_name, SecretString="denied-value")["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=denied_arn, ForceDeleteWithoutRecovery=True))

    control_arn = sm.create_secret(Name=control_name, SecretString="control-value")["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=control_arn, ForceDeleteWithoutRecovery=True))

    # Baseline: access works on both secrets before any resource policy is attached.
    before_denied = sm.get_secret_value(SecretId=denied_arn)["SecretString"]
    assert before_denied == "denied-value", (
        f"expected 'denied-value' before any policy is attached, got {before_denied!r}"
    )
    before_control = sm.get_secret_value(SecretId=control_arn)["SecretString"]
    assert before_control == "control-value", (
        f"expected 'control-value' before any policy is attached, got {before_control!r}"
    )

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    sm.put_resource_policy(SecretId=denied_arn, ResourcePolicy=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: sm.delete_resource_policy(SecretId=denied_arn))

    code, message = _error_code(lambda: sm.get_secret_value(SecretId=denied_arn))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {denied_arn} with an explicit deny in a resource-based policy"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: DescribeSecret still reports the value untouched -- this is a pure
    # authorization block, not a mutation of the secret itself.
    desc = sm.describe_secret(SecretId=denied_arn)
    assert desc["Name"] == denied_name, (
        f"expected DescribeSecret to still resolve {denied_name!r} while the deny is active, "
        f"got {desc.get('Name')!r}"
    )

    # Positive control in the same file: an unrelated secret with no such policy still works,
    # proving this is a targeted policy effect and not a global access breakage.
    control_value = sm.get_secret_value(SecretId=control_arn)["SecretString"]
    assert control_value == "control-value", (
        f"expected the unrelated control secret to stay unaffected, got {control_value!r}"
    )

    # Restore: removing the deny statement restores the identical call on the denied secret,
    # byte-identically -- the block is reversible, not a one-way lockout. Policy evaluation is
    # eventually consistent, so this is a bounded poll rather than a single call.
    sm.delete_resource_policy(SecretId=denied_arn)
    after_denied = _read_when_allowed(sm, denied_arn, timeout_s=60.0)["SecretString"]
    assert after_denied == "denied-value", (
        f"expected the denied secret's value unchanged after the deny/allow cycle, got "
        f"{after_denied!r}"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be denied, but it SUCCEEDED and returned {result!r}")


def _read_when_allowed(sm, secret_id, *, timeout_s, interval_s=3.0):
    """GetSecretValue retried through AccessDeniedException until the deadline, then re-raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.get_secret_value(SecretId=secret_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
