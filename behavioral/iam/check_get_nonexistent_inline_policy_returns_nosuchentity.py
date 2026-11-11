"""get-nonexistent-inline-policy-returns-nosuchentity."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-nonexistent-inline-policy-returns-nosuchentity"
GROUP = 'errors'
SERVICES = ['iam']

TRUST_POLICY_EC2 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. Raises if fn()
    succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


EXISTING_POLICY_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
)


def _capture_password_policy(iam):
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return None
        raise


def _restore_password_policy(iam, policy):
    if policy is None:
        try:
            iam.delete_account_password_policy()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
        return
    kwargs = {
        "MinimumPasswordLength": policy["MinimumPasswordLength"],
        "RequireSymbols": policy["RequireSymbols"],
        "RequireNumbers": policy["RequireNumbers"],
        "RequireUppercaseCharacters": policy["RequireUppercaseCharacters"],
        "RequireLowercaseCharacters": policy["RequireLowercaseCharacters"],
        "AllowUsersToChangePassword": policy["AllowUsersToChangePassword"],
        "HardExpiry": policy.get("HardExpiry", False),
    }
    if "MaxPasswordAge" in policy:
        kwargs["MaxPasswordAge"] = policy["MaxPasswordAge"]
    if "PasswordReusePrevention" in policy:
        kwargs["PasswordReusePrevention"] = policy["PasswordReusePrevention"]
    iam.update_account_password_policy(**kwargs)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iam-password-policy")
def run(ctx) -> None:
    """Get{Role,Group,User}Policy for a never-Put inline policy name returns NoSuchEntity (after the
    same call succeeds for a Put name), and GetAccountPasswordPolicy does so when none is set."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST_POLICY_EC2)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-existing", PolicyDocument=EXISTING_POLICY_DOC)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-behav-existing"))
    put_role = iam.get_role_policy(RoleName=role_name, PolicyName="sim2real-behav-existing")
    assert put_role["PolicyDocument"]["Statement"][0]["Action"] == "s3:ListBucket", (
        f"GetRolePolicy: positive control did not round-trip the Put document, got {put_role['PolicyDocument']}"
    )
    code_role, message = _error(
        lambda: iam.get_role_policy(RoleName=role_name, PolicyName="sim2real-behav-never-put")
    )
    assert code_role == "NoSuchEntity", f"GetRolePolicy: expected NoSuchEntity, got {code_role}"
    expected = "The role policy with name sim2real-behav-never-put cannot be found."
    assert message == expected, f"GetRolePolicy: expected message {expected!r}, got {message!r}"

    group_name = ctx.unique_name("sim2real-behav-group-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))
    iam.put_group_policy(GroupName=group_name, PolicyName="sim2real-behav-existing", PolicyDocument=EXISTING_POLICY_DOC)
    ctx.on_cleanup(lambda: iam.delete_group_policy(GroupName=group_name, PolicyName="sim2real-behav-existing"))
    put_group = iam.get_group_policy(GroupName=group_name, PolicyName="sim2real-behav-existing")
    assert put_group["PolicyDocument"]["Statement"][0]["Action"] == "s3:ListBucket", (
        f"GetGroupPolicy: positive control did not round-trip the Put document, got {put_group['PolicyDocument']}"
    )
    code_group, message = _error(
        lambda: iam.get_group_policy(GroupName=group_name, PolicyName="sim2real-behav-never-put")
    )
    assert code_group == "NoSuchEntity", f"GetGroupPolicy: expected NoSuchEntity, got {code_group}"
    expected = "The group policy with name sim2real-behav-never-put cannot be found."
    assert message == expected, f"GetGroupPolicy: expected message {expected!r}, got {message!r}"

    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    iam.put_user_policy(UserName=user_name, PolicyName="sim2real-behav-existing", PolicyDocument=EXISTING_POLICY_DOC)
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName="sim2real-behav-existing"))
    put_user = iam.get_user_policy(UserName=user_name, PolicyName="sim2real-behav-existing")
    assert put_user["PolicyDocument"]["Statement"][0]["Action"] == "s3:ListBucket", (
        f"GetUserPolicy: positive control did not round-trip the Put document, got {put_user['PolicyDocument']}"
    )
    code_user, message = _error(
        lambda: iam.get_user_policy(UserName=user_name, PolicyName="sim2real-behav-never-put")
    )
    assert code_user == "NoSuchEntity", f"GetUserPolicy: expected NoSuchEntity, got {code_user}"
    expected = "The user policy with name sim2real-behav-never-put cannot be found."
    assert message == expected, f"GetUserPolicy: expected message {expected!r}, got {message!r}"

    # The password policy is an account-global singleton: snapshot and restore it, and drive the
    # same set -> get -> delete -> get transition the other legs use as their positive control.
    original_policy = _capture_password_policy(iam)
    ctx.on_cleanup(lambda: _restore_password_policy(iam, original_policy))
    iam.update_account_password_policy(
        MinimumPasswordLength=10,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
    )
    fetched_policy = iam.get_account_password_policy()["PasswordPolicy"]
    assert fetched_policy["MinimumPasswordLength"] == 10, (
        f"GetAccountPasswordPolicy: positive control did not round-trip the Update, got {fetched_policy}"
    )
    iam.delete_account_password_policy()
    existing_code, message = _error(lambda: iam.get_account_password_policy())
    assert existing_code == "NoSuchEntity", (
        f"GetAccountPasswordPolicy: expected NoSuchEntity when unset, got {existing_code}"
    )
    expected = f"The Password Policy with domain name {ctx.account} cannot be found."
    assert message == expected, (
        f"GetAccountPasswordPolicy: expected message {expected!r}, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
