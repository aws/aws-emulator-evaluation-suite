"""op-contract-put-role-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-put-role-policy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_DOC = json.dumps(
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRolePolicy writes/overwrites an inline policy; a syntactically invalid document is rejected."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_DOC,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-inline-policy"
    doc_v1 = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-bucket/*"}
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc_v1))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    got = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    stmt = got["PolicyDocument"]["Statement"][0]
    assert stmt["Effect"] == "Allow"
    assert stmt["Action"] == "s3:GetObject"
    assert stmt["Resource"] == "arn:aws:s3:::example-bucket/*"

    # Same PolicyName re-PUT overwrites the document in place (no versioning for inline policies).
    doc_v2 = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-bucket-2/*"}
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc_v2))
    got2 = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    assert got2["PolicyDocument"]["Statement"][0]["Resource"] == "arn:aws:s3:::example-bucket-2/*"
    names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert names == [policy_name], f"overwrite should not create a second inline policy, got {names}"

    # Rejection boundary: a syntactically broken policy document is rejected, not stored.
    code, message = _error_code(
        lambda: iam.put_role_policy(
            RoleName=role_name, PolicyName="sim2real-bad-policy", PolicyDocument='{"Version": "2012-10-17", "Statement": ['
        )
    )
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "MalformedPolicyDocument", f"expected MalformedPolicyDocument, got {code}"
    expected = "Syntax errors in policy."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    remaining = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    assert "sim2real-bad-policy" not in remaining


def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
