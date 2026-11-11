"""put-get-user-inline-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-get-user-inline-policy"
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
    """PutUserPolicy -> GetUserPolicy returns the document."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))
    pol_name = "sim2real-behav-user-inline"
    iam.put_user_policy(UserName=user, PolicyName=pol_name, PolicyDocument=MINIMAL_POLICY_DOCUMENT)
    ctx.on_cleanup(lambda u=user, n=pol_name: iam.delete_user_policy(UserName=u, PolicyName=n))
    resp = iam.get_user_policy(UserName=user, PolicyName=pol_name)
    assert resp["PolicyName"] == pol_name
    assert resp["UserName"] == user
    assert resp["PolicyDocument"] == json.loads(MINIMAL_POLICY_DOCUMENT), (
        f"expected the exact document put, got {resp['PolicyDocument']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
