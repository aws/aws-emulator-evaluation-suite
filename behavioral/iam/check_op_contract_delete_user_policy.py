"""op-contract-deleteUserPolicy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteUserPolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_INLINE_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUserPolicy removes the inline policy; NoSuchEntity on an unknown policy name."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-behav-user-up-")
    iam.create_user(UserName=user_name)
    policy_name = "inline-policy"

    def _cleanup():
        try:
            iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_user(UserName=user_name)

    ctx.on_cleanup(_cleanup)

    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(_INLINE_DOC))
    assert policy_name in iam.list_user_policies(UserName=user_name)["PolicyNames"]

    # success path
    resp = iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert policy_name not in iam.list_user_policies(UserName=user_name)["PolicyNames"]
    code, code_msg = _client_error(lambda: iam.get_user_policy(UserName=user_name, PolicyName=policy_name))
    assert code == "NoSuchEntity", f"expected policy gone, got {code}"
    assert code_msg == f"The user policy with name {policy_name} cannot be found.", f"unexpected error message {code_msg!r}"

    # error boundary: deleting the policy a second time proves it stays gone, not just that an
    # always-unknown literal is rejected
    code2, code2_msg = _client_error(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))
    assert code2 == "NoSuchEntity", f"expected NoSuchEntity on double-delete, got {code2}"
    assert code2_msg == f"The user policy with name {policy_name} cannot be found.", f"unexpected error message {code2_msg!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
