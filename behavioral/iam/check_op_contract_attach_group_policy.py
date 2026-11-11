"""op-contract-attach-group-policy."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-attach-group-policy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_S3_READONLY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachGroupPolicy: success-path attachment shows up in ListAttachedGroupPolicies;
    error boundary is NoSuchEntityException for a GroupName that doesn't exist."""
    iam = ctx.client("iam")

    group_name = ctx.unique_name("sim2real-group-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))

    iam.attach_group_policy(GroupName=group_name, PolicyArn=_S3_READONLY_ARN)
    ctx.on_cleanup(lambda: iam.detach_group_policy(GroupName=group_name, PolicyArn=_S3_READONLY_ARN))

    attached = _poll_until(
        lambda: iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"],
        lambda ps: any(p["PolicyArn"] == _S3_READONLY_ARN for p in ps),
    )
    assert any(p["PolicyArn"] == _S3_READONLY_ARN for p in attached), (
        f"expected {_S3_READONLY_ARN} in ListAttachedGroupPolicies, got {attached}"
    )

    missing_group = ctx.unique_name("sim2real-nonexistent-group-")
    code, message = _error(
        lambda: iam.attach_group_policy(GroupName=missing_group, PolicyArn=_S3_READONLY_ARN)
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The group with name {missing_group} cannot be found."
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
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
