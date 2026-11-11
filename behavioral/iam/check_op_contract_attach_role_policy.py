"""op-contract-attach-role-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-attach-role-policy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_S3_READONLY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
# Service-linked-role-only managed policy: cannot be attached directly to a normal role.
_SERVICE_LINKED_ONLY_ARN = "arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachRolePolicy: success-path attachment shows up in ListAttachedRolePolicies; error
    boundary is PolicyNotAttachableException for a service-linked-role-only managed policy."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=_S3_READONLY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_S3_READONLY_ARN))

    attached = _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda ps: any(p["PolicyArn"] == _S3_READONLY_ARN for p in ps),
    )
    assert any(p["PolicyArn"] == _S3_READONLY_ARN for p in attached), (
        f"expected {_S3_READONLY_ARN} in ListAttachedRolePolicies, got "
        f"{[p['PolicyArn'] for p in attached]}"
    )

    code, message = _error(
        lambda: iam.attach_role_policy(RoleName=role_name, PolicyArn=_SERVICE_LINKED_ONLY_ARN)
    )
    assert code == "PolicyNotAttachable", f"expected PolicyNotAttachable, got {code}"
    expected = "Cannot attach AWS reserved policy to an IAM role."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    final_arns = {
        p["PolicyArn"]
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    }
    assert _SERVICE_LINKED_ONLY_ARN not in final_arns, (
        f"rejected attach must not appear in ListAttachedRolePolicies, got {final_arns}"
    )
    assert _S3_READONLY_ARN in final_arns, (
        f"prior successful attachment must still be present, got {final_arns}"
    )


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
