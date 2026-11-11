"""attach-list-user-policies."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

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

CHECK = "attach-list-user-policies"
GROUP = 'attach_detach'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachUserPolicy -> ListAttachedUserPolicies shows the attachment; DetachUserPolicy
    makes it disappear from that same independent read, and a second detach is rejected
    because the attachment no longer exists."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))
    arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=MINIMAL_POLICY_DOCUMENT,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))

    iam.attach_user_policy(UserName=user, PolicyArn=arn)
    resp = iam.list_attached_user_policies(UserName=user)
    attached_arns = [p["PolicyArn"] for p in resp["AttachedPolicies"]]
    assert arn in attached_arns, f"expected {arn} in ListAttachedUserPolicies, got {attached_arns}"

    iam.detach_user_policy(UserName=user, PolicyArn=arn)
    resp2 = iam.list_attached_user_policies(UserName=user)
    attached_after_detach = [p["PolicyArn"] for p in resp2["AttachedPolicies"]]
    assert arn not in attached_after_detach, (
        f"expected {arn} gone from ListAttachedUserPolicies after DetachUserPolicy, "
        f"still present: {attached_after_detach}"
    )

    code, message = _error(lambda: iam.detach_user_policy(UserName=user, PolicyArn=arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity detaching an already-detached policy, got {code}"
    assert message == f"Policy {arn} was not found.", (
        f"DetachUserPolicy on an already-detached policy message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
