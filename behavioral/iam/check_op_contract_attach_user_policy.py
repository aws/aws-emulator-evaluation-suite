"""op-contract-attach-user-policy."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-attach-user-policy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_EC2_READONLY_ARN = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachUserPolicy: success-path attachment shows up in ListAttachedUserPolicies; error
    boundary is NoSuchEntityException for a PolicyArn that doesn't exist."""
    iam = ctx.client("iam")

    user_name = ctx.unique_name("sim2real-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.attach_user_policy(UserName=user_name, PolicyArn=_EC2_READONLY_ARN)
    ctx.on_cleanup(lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=_EC2_READONLY_ARN))

    attached = _poll_until(
        lambda: iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"],
        lambda ps: any(p["PolicyArn"] == _EC2_READONLY_ARN for p in ps),
    )
    assert any(p["PolicyArn"] == _EC2_READONLY_ARN for p in attached), (
        f"expected {_EC2_READONLY_ARN} in {attached}"
    )

    bogus_policy_arn = "arn:aws:iam::aws:policy/sim2real-does-not-exist-policy"
    code, message = _error(
        lambda: iam.attach_user_policy(UserName=user_name, PolicyArn=bogus_policy_arn)
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"Policy {bogus_policy_arn} does not exist or is not attachable."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_until(probe, predicate, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
