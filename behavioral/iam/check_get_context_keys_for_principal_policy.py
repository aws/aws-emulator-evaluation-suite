"""get-context-keys-for-principal-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-context-keys-for-principal-policy"
GROUP = 'policy_simulation'
SERVICES = ['iam']

# A tiny policy whose Condition block references a single, unambiguous condition context key.
POLICY_WITH_CONTEXT_KEY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            }
        ],
    }
)


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, else raise."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:happy-path", "cap:c7", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetContextKeysForPrincipalPolicy returns the condition keys (aws:SourceIp) referenced by the
    user's own inline policy, and a nonexistent PolicySourceArn is rejected NoSuchEntity."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("ctxuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    user_arn = iam.get_user(UserName=user_name)["User"]["Arn"]

    iam.put_user_policy(
        UserName=user_name, PolicyName="sim2real-behav-ctx", PolicyDocument=POLICY_WITH_CONTEXT_KEY
    )
    ctx.on_cleanup(
        lambda: iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-behav-ctx")
    )

    resp = iam.get_context_keys_for_principal_policy(PolicySourceArn=user_arn)
    assert "aws:SourceIp" in resp["ContextKeyNames"], (
        f"expected aws:SourceIp from the user's own inline policy, got {resp['ContextKeyNames']}"
    )

    account = ctx.client("sts").get_caller_identity()["Account"]
    missing_name = ctx.unique_name("missing-")
    bad_arn = f"arn:aws:iam::{account}:user/{missing_name}"
    code, message = _error(
        lambda: iam.get_context_keys_for_principal_policy(PolicySourceArn=bad_arn)
    )
    assert code == "NoSuchEntity", (
        f"expected NoSuchEntity for a nonexistent PolicySourceArn, got {code}"
    )
    expected = "Unable to retrieve specified IAM entity."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
