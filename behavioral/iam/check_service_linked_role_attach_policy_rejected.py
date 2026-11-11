"""service-linked-role-attach-policy-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-linked-role-attach-policy-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
_INLINE_POLICY_DOC = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
    '"Action": "s3:ListAllMyBuckets", "Resource": "*"}]}'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachRolePolicy and PutRolePolicy must both be rejected with
    UnmodifiableEntity for a service-linked role -- only the owning service is
    allowed to manage its permissions."""
    iam = ctx.client("iam")
    suffix = uuid.uuid4().hex[:20]

    role_name = iam.create_service_linked_role(
        AWSServiceName="autoscaling.amazonaws.com", CustomSuffix=suffix
    )["Role"]["RoleName"]
    ctx.on_cleanup(lambda: _best_effort_delete_slr(iam, role_name))

    # A service-linked role is created with its owning service's own baseline
    # policy already attached (e.g. the AutoScalingServiceRolePolicy) -- that is
    # not something either rejected call below is allowed to change, so capture
    # it as the baseline to diff against rather than assuming an empty list.
    baseline_attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    baseline_inline = iam.list_role_policies(RoleName=role_name)["PolicyNames"]

    code_attach, msg_attach = _error(
        lambda: iam.attach_role_policy(RoleName=role_name, PolicyArn=_MANAGED_POLICY_ARN)
    )
    assert code_attach == "UnmodifiableEntity", (
        f"expected UnmodifiableEntity from AttachRolePolicy on a service-linked role, got {code_attach}"
    )
    want = (f"Cannot perform the operation on the protected role '{role_name}' - "
            "this role is only modifiable by AWS")
    assert msg_attach == want, f"AttachRolePolicy message: wanted {want!r}, got {msg_attach!r}"

    code_inline, msg_inline = _error(
        lambda: iam.put_role_policy(
            RoleName=role_name,
            PolicyName=ctx.unique_name("sim2real-slrinline-"),
            PolicyDocument=_INLINE_POLICY_DOC,
        )
    )
    assert code_inline == "UnmodifiableEntity", (
        f"expected UnmodifiableEntity from PutRolePolicy on a service-linked role, got {code_inline}"
    )
    assert msg_inline == want, f"PutRolePolicy message: wanted {want!r}, got {msg_inline!r}"

    # neither rejected call must have modified the role's permissions: the
    # attached-policy set must be exactly the pre-existing baseline (in
    # particular, must not include the policy we tried to attach), and no
    # inline policy must have been added.
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    assert attached == baseline_attached
    attached_arns = {p["PolicyArn"] for p in attached}
    assert _MANAGED_POLICY_ARN not in attached_arns
    inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert inline_names == baseline_inline

    # Positive control: the identical AttachRolePolicy and PutRolePolicy calls succeed
    # against an ordinary, unprotected role -- without this, "rejected" on the
    # service-linked role would be indistinguishable from a target that rejects
    # AttachRolePolicy/PutRolePolicy for every role.
    control_role = ctx.unique_name("sim2real-slrcontrol-")
    trust_policy = (
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=control_role, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, control_role))

    iam.attach_role_policy(RoleName=control_role, PolicyArn=_MANAGED_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=control_role, PolicyArn=_MANAGED_POLICY_ARN)
    )
    control_attached_arns = {
        p["PolicyArn"]
        for p in iam.list_attached_role_policies(RoleName=control_role)["AttachedPolicies"]
    }
    assert _MANAGED_POLICY_ARN in control_attached_arns, (
        "positive control failed: AttachRolePolicy should succeed against an ordinary role"
    )

    control_inline_name = ctx.unique_name("sim2real-slrcontrolinline-")
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=control_role, PolicyName=control_inline_name)
    )
    iam.put_role_policy(
        RoleName=control_role,
        PolicyName=control_inline_name,
        PolicyDocument=_INLINE_POLICY_DOC,
    )
    control_inline_names = iam.list_role_policies(RoleName=control_role)["PolicyNames"]
    assert control_inline_name in control_inline_names, (
        "positive control failed: PutRolePolicy should succeed against an ordinary role"
    )


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _best_effort_delete_slr(iam, role_name: str) -> None:
    try:
        iam.delete_service_linked_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
