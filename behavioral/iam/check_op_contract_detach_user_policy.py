"""op-contract-detachUserPolicy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detachUserPolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_DENY_ALL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachUserPolicy removes the attachment; NoSuchEntity when the policy isn't attached."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-behav-user-detach-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.attach_user_policy(UserName=user_name, PolicyArn=_DENY_ALL_POLICY_ARN)
    attached = [p["PolicyArn"] for p in iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]]
    assert _DENY_ALL_POLICY_ARN in attached, f"expected {_DENY_ALL_POLICY_ARN} attached, got {attached}"

    # success path
    resp = iam.detach_user_policy(UserName=user_name, PolicyArn=_DENY_ALL_POLICY_ARN)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, f"unexpected detach response: {resp}"
    attached_after = [
        p["PolicyArn"] for p in iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
    ]
    assert _DENY_ALL_POLICY_ARN not in attached_after, f"policy still attached after detach: {attached_after}"

    # error boundary: detaching a policy that is not currently attached -> NoSuchEntityException
    code, message = _error(lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=_DENY_ALL_POLICY_ARN))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected_message = f"Policy {_DENY_ALL_POLICY_ARN} was not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected NoSuchEntity but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
