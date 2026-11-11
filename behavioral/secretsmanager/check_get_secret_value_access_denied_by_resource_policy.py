"""get-secret-value-access-denied-by-resource-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-secret-value-access-denied-by-resource-policy"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A resource policy denying GetSecretValue to the account blocks the caller's own read, leaves
    DescribeSecret and an unrelated secret unaffected, and deleting it restores the original value.
    Policy evaluation is eventually consistent both ways, so both transitions are bounded polls.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]

    denied_name = ctx.unique_name("sim2real-behav-denysecret-")
    denied = sm.create_secret(Name=denied_name, SecretString="denied-secret-value")
    denied_arn = denied["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=denied_arn, ForceDeleteWithoutRecovery=True))

    control_name = ctx.unique_name("sim2real-behav-controlsecret-")
    control = sm.create_secret(Name=control_name, SecretString="control-secret-value")
    control_arn = control["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=control_arn, ForceDeleteWithoutRecovery=True))

    # Positive control BEFORE: these credentials read this very secret before any
    # resource policy exists, so the later denial cannot be an ambient permissions gap.
    before = sm.get_secret_value(SecretId=denied_arn)
    assert before["SecretString"] == "denied-secret-value", (
        f"baseline read before any policy must return the value written at creation, "
        f"got {before['SecretString']!r}"
    )

    # Denying the account root ARN denies every principal in the account (an explicit Deny
    # always wins over any identity-based Allow), so this blocks our own caller too.
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

    err = _poll_for_code(
        lambda: _error(lambda: sm.get_secret_value(SecretId=denied_arn)),
        "AccessDeniedException",
    )
    assert err["Code"] == "AccessDeniedException", f"expected AccessDeniedException, got {err}"
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {denied_arn} with an explicit deny in a resource-based policy"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent / scoped: the deny only targets GetSecretValue -- DescribeSecret on the
    # very same secret (a different action) still succeeds, proving no value was ever
    # obtainable through the denied call and no broader lockout occurred.
    described = sm.describe_secret(SecretId=denied_arn)
    assert described["Name"] == denied_name, (
        f"DescribeSecret must still resolve the denied secret's metadata, "
        f"got {described.get('Name')!r}"
    )

    # Positive control: the same credentials retrieve an unrelated secret with no such policy.
    control_value = sm.get_secret_value(SecretId=control_arn)
    assert control_value["SecretString"] == "control-secret-value", (
        f"an unrelated secret must be unaffected by the denied secret's policy, "
        f"got {control_value['SecretString']!r}"
    )

    # Restore: removing the resource policy must bring back the identical call, with the
    # original value, proving the block was the policy and nothing else.
    sm.delete_resource_policy(SecretId=denied_arn)
    after = _poll_until_success(lambda: sm.get_secret_value(SecretId=denied_arn))
    assert after["SecretString"] == "denied-secret-value", (
        f"restoring access must return the original value, got {after['SecretString']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore Error dict, or a Code no service returns when the call
    succeeds (the poll below waits through the policy's propagation window)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    return {"Code": "<call succeeded>", "Message": repr(result)}


def _poll_for_code(probe, expected_code, *, timeout_s=60.0, interval_s=3.0):
    """Bounded retry for resource-policy evaluation's eventual consistency; returns the matching
    Error dict and raises on timeout rather than returning the last (wrong) observation."""
    import time

    deadline = time.monotonic() + timeout_s
    err = probe()
    while err["Code"] != expected_code:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"never observed {expected_code} within {timeout_s}s; last error was {err!r}"
            )
        time.sleep(interval_s)
        err = probe()
    return err


def _poll_until_success(fn, *, timeout_s=60.0, interval_s=3.0):
    """Bounded retry for the deny's removal to take effect; raises on timeout."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
