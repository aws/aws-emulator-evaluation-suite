"""op-contract-detachRolePolicy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detachRolePolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_DENY_ALL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSDenyAll"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachRolePolicy removes the attachment; NoSuchEntity when the policy isn't attached; the
    rejection is a state check, not a permanent break -- the identical call succeeds once re-attached.
    """
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-role-detach-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.attach_role_policy(RoleName=role_name, PolicyArn=_DENY_ALL_POLICY_ARN)
    attached = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]]
    assert _DENY_ALL_POLICY_ARN in attached, f"expected {_DENY_ALL_POLICY_ARN} attached, got {attached}"

    # success path
    resp = iam.detach_role_policy(RoleName=role_name, PolicyArn=_DENY_ALL_POLICY_ARN)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 from DetachRolePolicy, got {status}"
    attached_after = [
        p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    ]
    assert _DENY_ALL_POLICY_ARN not in attached_after, f"expected detached, still attached: {attached_after}"

    # error boundary: detaching a policy that is not currently attached -> NoSuchEntityException
    code, code_msg = _client_error(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_DENY_ALL_POLICY_ARN))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    assert code_msg == f"Policy {_DENY_ALL_POLICY_ARN} was not found.", f"unexpected error message {code_msg!r}"

    # restore: prove the refusal tracks attachment state rather than a permanent break -- the
    # identical call succeeds again once the policy is re-attached.
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_DENY_ALL_POLICY_ARN)
    iam.detach_role_policy(RoleName=role_name, PolicyArn=_DENY_ALL_POLICY_ARN)
    attached_final = [
        p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    ]
    assert _DENY_ALL_POLICY_ARN not in attached_final, f"expected detached after restore, still attached: {attached_final}"


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
