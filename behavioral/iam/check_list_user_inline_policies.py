"""list-user-inline-policies."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-user-inline-policies"
GROUP = 'inline_policies'
SERVICES = ['iam']

MINIMAL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:GetUser",
                "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
            }
        ],
    }
)

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUserPolicies returns exactly the inline policy names put on a user; a
    nonexistent user is rejected with NoSuchEntity."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))
    pol_name = "sim2real-behav-user-inline-list"
    iam.put_user_policy(UserName=user, PolicyName=pol_name, PolicyDocument=MINIMAL_POLICY_DOCUMENT)
    ctx.on_cleanup(lambda u=user, n=pol_name: iam.delete_user_policy(UserName=u, PolicyName=n))
    resp = iam.list_user_policies(UserName=user)
    assert resp["PolicyNames"] == [pol_name], f"expected exactly [{pol_name}], got {resp['PolicyNames']}"

    bogus_user = ctx.unique_name("sim2real-behav-nonexistent-user-")
    try:
        iam.list_user_policies(UserName=bogus_user)
        raise AssertionError(f"expected NoSuchEntity for nonexistent user {bogus_user}, call succeeded")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
        message = exc.response["Error"].get("Message")
        expected_message = f"The user with name {bogus_user} cannot be found."
        assert message == expected_message, (
            f"expected AWS's exact message {expected_message!r}, got {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
