"""server-side-resource-policy-blocks-get-secret-value."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-resource-policy-blocks-get-secret-value"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A resource policy denying GetSecretValue to the caller makes the next read fail with
    AccessDeniedException while DescribeSecret still succeeds, and deleting the policy restores
    the read; the caller could read the secret before the policy was applied."""
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]

    secret_name = ctx.unique_name("sim2real-behav-rpolicy-")
    secret = sm.create_secret(
        Name=secret_name,
        SecretString="server-side-secret",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    sm.get_secret_value(SecretId=secret_arn)

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyCallerRead",
            "Effect": "Deny",
            "Principal": {"AWS": caller_arn},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": secret_arn,
        }],
    }
    sm.put_resource_policy(SecretId=secret_arn, ResourcePolicy=json.dumps(deny_policy))
    fetched_policy = json.loads(sm.get_resource_policy(SecretId=secret_arn)["ResourcePolicy"])
    assert fetched_policy["Statement"][0]["Effect"] == "Deny", (
        f"expected the stored statement to be a Deny, got {fetched_policy['Statement'][0]!r}"
    )

    code, message = _error_code(lambda: sm.get_secret_value(SecretId=secret_arn))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {secret_arn} with an explicit deny in a resource-based policy"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # DescribeSecret must still succeed, so the denial above is this policy, not an ambient failure.
    described = sm.describe_secret(SecretId=secret_arn)
    assert described["ARN"] == secret_arn, (
        f"DescribeSecret is not denied by this policy and must still resolve, got {described.get('ARN')!r}"
    )

    sm.delete_resource_policy(SecretId=secret_arn)
    _poll_until_success(lambda: sm.get_secret_value(SecretId=secret_arn), timeout_s=60)


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be denied, but it SUCCEEDED and returned {result!r}")


def _poll_until_success(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
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
