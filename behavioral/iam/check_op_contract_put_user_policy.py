"""op-contract-put-user-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-put-user-policy"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutUserPolicy writes/overwrites an inline policy on a user; a nonexistent user is rejected."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "sim2real-inline-policy"
    doc_v1 = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "arn:aws:sqs:*:*:example-queue"}
        ],
    }
    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc_v1))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    got = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
    stmt = got["PolicyDocument"]["Statement"][0]
    assert stmt["Effect"] == "Allow", f"expected Effect=Allow from the v1 document, got {stmt!r}"
    assert stmt["Action"] == "sqs:SendMessage", f"expected Action=sqs:SendMessage from the v1 document, got {stmt!r}"

    # Overwrite in place: same PolicyName, different document.
    doc_v2 = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "sqs:SendMessage", "Resource": "arn:aws:sqs:*:*:example-queue"}
        ],
    }
    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc_v2))
    got2 = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
    effect2 = got2["PolicyDocument"]["Statement"][0]["Effect"]
    assert effect2 == "Deny", f"expected the v2 write to replace v1 in place (Effect=Deny), got {effect2!r}"
    policy_names = iam.list_user_policies(UserName=user_name)["PolicyNames"]
    assert policy_names == [policy_name], f"expected exactly one inline policy {policy_name!r}, got {policy_names!r}"

    # Error boundary: the target user does not exist.
    ghost_user = ctx.unique_name("sim2real-ghost-user-")
    code, message = _error_code(
        lambda: iam.put_user_policy(
            UserName=ghost_user,
            PolicyName="whatever",
            PolicyDocument=json.dumps(doc_v1),
        )
    )
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The user with name {ghost_user} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises: a target
    accepting what real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
