"""op-contract-listUserPolicies-single-inline."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listUserPolicies-single-inline"
GROUP = "error-semantics"
SERVICES = ["iam"]

_INLINE_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]}
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Success path lists exactly the inline policy names put on the user; a missing user yields NoSuchEntityException."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-batch09-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    inline_name = "sim2real-batch09-inline"
    iam.put_user_policy(UserName=user_name, PolicyName=inline_name, PolicyDocument=_INLINE_DOC)
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=inline_name))

    resp = iam.list_user_policies(UserName=user_name)
    assert resp["PolicyNames"] == [inline_name], f"expected exactly [{inline_name}], got {resp['PolicyNames']}"
    assert resp["IsTruncated"] is False

    # Error boundary: UserName that does not exist.
    bogus_user = ctx.unique_name("sim2real-batch09-missing-user-")
    code, message = _error(lambda: iam.list_user_policies(UserName=bogus_user))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The user with name {bogus_user} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
