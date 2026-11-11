"""delete-role-inline-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

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

CHECK = "delete-role-inline-policy"
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

def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRolePolicy removes the inline policy: an independent read confirms it was there,
    then that it is gone with the specific not-found code, and a further delete of the same
    now-gone name fails the identical way."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    resource_tags = [{"Key": "sim2real-behav-check", "Value": CHECK}]
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    pol_name = "sim2real-behav-inline-del"
    iam.put_role_policy(RoleName=role, PolicyName=pol_name, PolicyDocument=MINIMAL_POLICY_DOCUMENT)
    ctx.on_cleanup(lambda r=role, n=pol_name: _ignore_missing(lambda: iam.delete_role_policy(RoleName=r, PolicyName=n)))

    listed_before = iam.list_role_policies(RoleName=role)["PolicyNames"]
    assert pol_name in listed_before, f"expected {pol_name} present before delete, got {listed_before}"
    doc_before = iam.get_role_policy(RoleName=role, PolicyName=pol_name)["PolicyDocument"]
    assert doc_before == json.loads(MINIMAL_POLICY_DOCUMENT), (
        f"expected the put document back, got {doc_before}"
    )

    iam.delete_role_policy(RoleName=role, PolicyName=pol_name)

    listed_after = iam.list_role_policies(RoleName=role)["PolicyNames"]
    assert pol_name not in listed_after, f"expected {pol_name} absent after delete, got {listed_after}"
    code, code_msg = _client_error(lambda: iam.get_role_policy(RoleName=role, PolicyName=pol_name))
    assert code == "NoSuchEntity", f"expected NoSuchEntity reading the deleted policy, got {code}"
    assert code_msg == f"The role policy with name {pol_name} cannot be found.", f"unexpected error message {code_msg!r}"
    code2, code2_msg = _client_error(lambda: iam.delete_role_policy(RoleName=role, PolicyName=pol_name))
    assert code2 == "NoSuchEntity", (
        f"expected NoSuchEntity deleting the already-deleted policy, got {code2}"
    )
    assert code2_msg == f"The role policy with name {pol_name} cannot be found.", f"unexpected error message {code2_msg!r}"


def _ignore_missing(fn):
    """Teardown: run fn(), tolerating only NoSuchEntity for a resource the check already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
