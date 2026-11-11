"""service-linked-role-inline-policy-attach-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-linked-role-inline-policy-attach-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_SLR_SERVICE_NAME = "supportplans.amazonaws.com"
_SLR_ROLE_NAME = "AWSServiceRoleForSupportPlans"


def _error_code(fn):
    """``(code, message)`` of a refused call; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRolePolicy on the AWSServiceRoleForSupportPlans service-linked role fails with
    UnmodifiableEntity and its exact message and creates no inline policy, while the same
    call on an ordinary role succeeds and GetRolePolicy returns the policy."""
    iam = ctx.client("iam")

    created_here = False
    try:
        iam.create_service_linked_role(AWSServiceName=_SLR_SERVICE_NAME)
        created_here = True
    except iam.exceptions.EntityAlreadyExistsException:
        pass  # role pre-exists in this account; run the negative test against it as-is

    if created_here:
        def _cleanup_slr():
            try:
                iam.delete_service_linked_role(RoleName=_SLR_ROLE_NAME)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_cleanup_slr)

    inline_policy_name = ctx.unique_name("sim2real-behav-slr-policy-")
    policy_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}
    )

    code, message = _error_code(
        lambda: iam.put_role_policy(
            RoleName=_SLR_ROLE_NAME, PolicyName=inline_policy_name, PolicyDocument=policy_doc
        )
    )
    assert code == "UnmodifiableEntity", (
        f"expected UnmodifiableEntity attaching an inline policy to a service-linked role, got {code!r}"
    )
    expected = (
        f"Cannot perform the operation on the protected role '{_SLR_ROLE_NAME}' - "
        "this role is only modifiable by AWS"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Forbidden effect did not happen: the policy was never created on the SLR.
    existing_policies = iam.list_role_policies(RoleName=_SLR_ROLE_NAME)["PolicyNames"]
    assert inline_policy_name not in existing_policies, (
        f"expected {inline_policy_name!r} to be absent from the SLR's inline policies, "
        f"found it in {existing_policies!r}"
    )

    # Positive control: the same PutRolePolicy call succeeds against an ordinary role.
    control_role = ctx.unique_name("sim2real-behav-control-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(
        RoleName=control_role,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=control_role))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=control_role, PolicyName=inline_policy_name))
    iam.put_role_policy(RoleName=control_role, PolicyName=inline_policy_name, PolicyDocument=policy_doc)
    attached = iam.get_role_policy(RoleName=control_role, PolicyName=inline_policy_name)
    expected_action = json.loads(policy_doc)["Statement"][0]["Action"]
    assert expected_action in str(attached["PolicyDocument"]), (
        f"expected the control role's inline policy document to contain action {expected_action!r}, "
        f"got {attached['PolicyDocument']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
