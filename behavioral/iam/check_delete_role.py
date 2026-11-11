"""delete-role."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

CHECK = "delete-role"
GROUP = 'role_lifecycle'
SERVICES = ['iam']

ERR_NO_SUCH_ENTITY = "NoSuchEntity"

INLINE_POLICY_DOCUMENT = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
)


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRole removes the role: an independent GetRole returns NoSuchEntity, a mutation
    (PutRolePolicy) on the dead role also fails NoSuchEntity rather than silently landing, and the
    freed name is reusable by a subsequent CreateRole."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=name: iam.delete_role(RoleName=n))
    iam.delete_role(RoleName=name)

    read_code, read_message = _error_code(lambda: iam.get_role(RoleName=name))
    assert read_code == ERR_NO_SUCH_ENTITY, f"expected GetRole on deleted role NoSuchEntity, got {read_code}"
    assert read_message == f"The role with name {name} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {read_message!r}"
    )

    mutate_code, mutate_message = _error_code(
        lambda: iam.put_role_policy(
            RoleName=name, PolicyName="sim2real-behav-inline", PolicyDocument=INLINE_POLICY_DOCUMENT
        )
    )
    assert mutate_code == ERR_NO_SUCH_ENTITY, (
        f"expected PutRolePolicy on deleted role NoSuchEntity, got {mutate_code}"
    )
    assert mutate_message == f"The role with name {name} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {mutate_message!r}"
    )

    recreated = iam.create_role(RoleName=name, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    assert recreated["Role"]["RoleName"] == name, "freed role name should be reusable by CreateRole"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
