"""malformed-policy-document-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "malformed-policy-document-rejected"
GROUP = 'policy_document_validation'
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

TRUST_POLICY_LAMBDA = json.dumps(
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

ALLOW_S3_LIST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)

ALLOW_EC2_DESCRIBE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}],
    }
)


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-password-policy")
def run(ctx) -> None:
    """Invalid policy JSON is rejected MalformedPolicyDocument without persisting anything by
    CreatePolicyVersion, Put{Group,Role,User}Policy and UpdateAssumeRolePolicy, each after a valid
    call succeeds; a valid UpdateAccountPasswordPolicy round-trips."""
    iam = ctx.client("iam")

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy_arn = iam.create_policy(PolicyName=policy_name, PolicyDocument=ALLOW_S3_LIST_POLICY)[
        "Policy"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))
    initial_versions = {v["VersionId"] for v in iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]}
    assert len(initial_versions) == 1, f"a freshly created policy must have exactly one version: {initial_versions}"

    good_version_id = iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=ALLOW_EC2_DESCRIBE_POLICY, SetAsDefault=False
    )["PolicyVersion"]["VersionId"]
    ctx.on_cleanup(lambda: iam.delete_policy_version(PolicyArn=policy_arn, VersionId=good_version_id))
    versions_after_good = {v["VersionId"] for v in iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]}
    assert versions_after_good == initial_versions | {good_version_id}, (
        f"positive control: a valid CreatePolicyVersion must be stored, got {versions_after_good}"
    )

    code_cpv, code_cpv_message = _error(
        lambda: iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument="{not valid json")
    )
    assert code_cpv == "MalformedPolicyDocument", f"CreatePolicyVersion: expected MalformedPolicyDocument, got {code_cpv}"
    expected = "Syntax errors in policy."
    assert code_cpv_message == expected, f"expected message {expected!r}, got {code_cpv_message!r}"
    versions_after_bad = {v["VersionId"] for v in iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]}
    assert versions_after_bad == versions_after_good, (
        f"malformed CreatePolicyVersion must not persist a new version: {versions_after_bad}"
    )

    group_name = ctx.unique_name("sim2real-behav-group-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))
    good_gpolicy = "sim2real-behav-good"
    iam.put_group_policy(GroupName=group_name, PolicyName=good_gpolicy, PolicyDocument=ALLOW_S3_LIST_POLICY)
    ctx.on_cleanup(lambda: iam.delete_group_policy(GroupName=group_name, PolicyName=good_gpolicy))
    got_gpolicy = iam.get_group_policy(GroupName=group_name, PolicyName=good_gpolicy)["PolicyDocument"]
    assert got_gpolicy["Statement"][0]["Action"] == "s3:ListBucket", (
        f"positive control: a valid PutGroupPolicy must round-trip, got {got_gpolicy}"
    )

    code_pgp, code_pgp_message = _error(
        lambda: iam.put_group_policy(
            GroupName=group_name, PolicyName="sim2real-behav-bad", PolicyDocument="{not valid json"
        )
    )
    assert code_pgp == "MalformedPolicyDocument", f"PutGroupPolicy: expected MalformedPolicyDocument, got {code_pgp}"
    expected = "Syntax errors in policy."
    assert code_pgp_message == expected, f"expected message {expected!r}, got {code_pgp_message!r}"
    remaining_gpolicies = iam.list_group_policies(GroupName=group_name)["PolicyNames"]
    assert remaining_gpolicies == [good_gpolicy], (
        f"malformed PutGroupPolicy must leave only the good policy in place, got {remaining_gpolicies}"
    )

    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST_POLICY_EC2)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    good_rpolicy = "sim2real-behav-good"
    iam.put_role_policy(RoleName=role_name, PolicyName=good_rpolicy, PolicyDocument=ALLOW_S3_LIST_POLICY)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=good_rpolicy))
    got_rpolicy = iam.get_role_policy(RoleName=role_name, PolicyName=good_rpolicy)["PolicyDocument"]
    assert got_rpolicy["Statement"][0]["Action"] == "s3:ListBucket", (
        f"positive control: a valid PutRolePolicy must round-trip, got {got_rpolicy}"
    )

    code_prp, code_prp_message = _error(
        lambda: iam.put_role_policy(
            RoleName=role_name, PolicyName="sim2real-behav-bad", PolicyDocument="{not valid json"
        )
    )
    assert code_prp == "MalformedPolicyDocument", f"PutRolePolicy: expected MalformedPolicyDocument, got {code_prp}"
    expected = "Syntax errors in policy."
    assert code_prp_message == expected, f"expected message {expected!r}, got {code_prp_message!r}"
    remaining_rpolicies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert remaining_rpolicies == [good_rpolicy], (
        f"malformed PutRolePolicy must leave only the good policy in place, got {remaining_rpolicies}"
    )

    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    good_upolicy = "sim2real-behav-good"
    iam.put_user_policy(UserName=user_name, PolicyName=good_upolicy, PolicyDocument=ALLOW_S3_LIST_POLICY)
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=good_upolicy))
    got_upolicy = iam.get_user_policy(UserName=user_name, PolicyName=good_upolicy)["PolicyDocument"]
    assert got_upolicy["Statement"][0]["Action"] == "s3:ListBucket", (
        f"positive control: a valid PutUserPolicy must round-trip, got {got_upolicy}"
    )

    code_pup, code_pup_message = _error(
        lambda: iam.put_user_policy(
            UserName=user_name, PolicyName="sim2real-behav-bad", PolicyDocument="{not valid json"
        )
    )
    assert code_pup == "MalformedPolicyDocument", f"PutUserPolicy: expected MalformedPolicyDocument, got {code_pup}"
    expected = "Syntax errors in policy."
    assert code_pup_message == expected, f"expected message {expected!r}, got {code_pup_message!r}"
    remaining_upolicies = iam.list_user_policies(UserName=user_name)["PolicyNames"]
    assert remaining_upolicies == [good_upolicy], (
        f"malformed PutUserPolicy must leave only the good policy in place, got {remaining_upolicies}"
    )

    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=TRUST_POLICY_LAMBDA)
    got_role_good = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert got_role_good["Statement"][0]["Principal"]["Service"] == "lambda.amazonaws.com", (
        f"positive control: a valid UpdateAssumeRolePolicy must be applied, got {got_role_good}"
    )

    code_uarp, code_uarp_message = _error(
        lambda: iam.update_assume_role_policy(RoleName=role_name, PolicyDocument="{not valid json")
    )
    assert code_uarp == "MalformedPolicyDocument", (
        f"UpdateAssumeRolePolicy: expected MalformedPolicyDocument, got {code_uarp}"
    )
    expected = "This policy contains invalid Json"
    assert code_uarp_message == expected, f"expected message {expected!r}, got {code_uarp_message!r}"
    got_role = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert got_role["Statement"][0]["Principal"]["Service"] == "lambda.amazonaws.com", (
        f"rejected UpdateAssumeRolePolicy must not change the existing trust document, got {got_role}"
    )

    # UpdateAccountPasswordPolicy takes typed parameters, not JSON, so only its valid round-trip is
    # checked. The password policy is an account-wide singleton: reset first, delete afterward.
    try:
        iam.delete_account_password_policy()
    except ClientError:
        pass
    iam.update_account_password_policy(MinimumPasswordLength=10, RequireNumbers=True)
    ctx.on_cleanup(lambda: iam.delete_account_password_policy())
    got_policy = iam.get_account_password_policy()["PasswordPolicy"]
    assert got_policy["MinimumPasswordLength"] == 10, (
        f"UpdateAccountPasswordPolicy: expected MinimumPasswordLength=10, got {got_policy}"
    )
    assert got_policy["RequireNumbers"] is True, (
        f"UpdateAccountPasswordPolicy: expected RequireNumbers=True, got {got_policy}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
