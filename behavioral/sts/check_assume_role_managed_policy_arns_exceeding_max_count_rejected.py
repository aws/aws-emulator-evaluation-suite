"""assume-role-managed-policy-arns-exceeding-max-count-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-managed-policy-arns-exceeding-max-count-rejected"
GROUP = "error-semantics"
SERVICES = ["sts"]

# 11 distinct, always-present AWS managed policies (owned by the "aws" account,
# so existence is never in question) -- one more than the documented "up to 10
# managed policy ARNs" limit for AssumeRole's PolicyArns parameter.
_ELEVEN_AWS_MANAGED_POLICIES = [
    "arn:aws:iam::aws:policy/ReadOnlyAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonRDSReadOnlyAccess",
    "arn:aws:iam::aws:policy/AWSLambda_ReadOnlyAccess",
    "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonSNSReadOnlyAccess",
    "arn:aws:iam::aws:policy/AmazonSQSReadOnlyAccess",
]

_OVER_LIMIT_MESSAGE = (
    "The limit of ARNs for the PolicyArns parameter was exceeded. 10 ARNs can be requested "
    "at most in an API request."
)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Supplying more than 10 PolicyArns on AssumeRole is rejected as an
    out-of-range input error, while the identical call with 2 managed policy
    ARNs on the same role succeeds."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-polycount-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_if_exists(iam, role_name))

    two_policy_arns = [{"arn": a} for a in _ELEVEN_AWS_MANAGED_POLICIES[:2]]
    eleven_policy_arns = [{"arn": a} for a in _ELEVEN_AWS_MANAGED_POLICIES]

    # Positive control first: 2 managed policy ARNs (well under the limit)
    # succeeds. IAM trust propagation can lag a few seconds after CreateRole,
    # so poll rather than trust the first attempt.
    control = _poll_until(
        lambda: _try_assume(sts, role_arn, "sim2real-polycount-ctrl", two_policy_arns),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert "Credentials" in control, f"control assume_role with 2 managed policy ARNs returned no Credentials: {control!r}"
    assert control["PackedPolicySize"] < 100, (
        f"expected PackedPolicySize < 100 for a 2-ARN control call, got {control['PackedPolicySize']!r}"
    )

    # Break exactly one thing: 11 managed policy ARNs, one over the documented
    # 10-ARN limit (the ARNs themselves are all real, always-present AWS
    # managed policies, so this cannot be confused with an "ARN doesn't exist"
    # failure).
    code, message = _refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sim2real-polycount-over",
            PolicyArns=eleven_policy_arns,
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == _OVER_LIMIT_MESSAGE, message

    # Effect absent: retrying the identical over-count request still fails the
    # same way -- STS is stateless, so no session was ever created for it.
    code_again, message_again = _refusal(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sim2real-polycount-over2",
            PolicyArns=eleven_policy_arns,
        )
    )
    assert code_again == "ValidationError", f"expected ValidationError on retry of the same over-count call, got {code_again!r}"
    assert message_again == _OVER_LIMIT_MESSAGE, message_again

    # Positive control, repeated: the exact same role/call with only 2 policy
    # ARNs still succeeds, proving the rejection above was specific to the
    # count, not a blanket failure of this role/session.
    control_2 = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="sim2real-polycount-ctrl2", PolicyArns=two_policy_arns
    )
    assert "Credentials" in control_2, (
        f"post-rejection control assume_role with 2 managed policy ARNs returned no Credentials: {control_2!r}"
    )


def _try_assume(sts_client, role_arn, session_name, policy_arns):
    try:
        return sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=session_name, PolicyArns=policy_arns
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError("condition not met within timeout")
    return result


def _refusal(fn):
    """(code, message) of the error ``fn`` raises; AssertionError when it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED: {result!r}")

def _delete_role_if_exists(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
