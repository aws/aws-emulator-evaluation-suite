"""assume-role-with-web-identity-nonexistent-role-denied."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-with-web-identity-nonexistent-role-denied"
GROUP = "overly-permissive"
SERVICES = ["sts"]

# Two dot-joined segments, not three: not a parseable JWT at all.
_GARBAGE_TOKEN = "eyJhbGciOiJSUzI1NiJ9.test-token"
#: STS's refusal of that token, measured on real AWS.
_GARBAGE_TOKEN_MESSAGE = (
    "The ID Token provided is not a valid JWT. (You may see this error if you sent an Access Token)")


def _error(fn):
    """(code, HTTP status, message, None) of the error fn() raises, or (None, None, None, resp)."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return (err["Code"], exc.response["ResponseMetadata"].get("HTTPStatusCode"),
                err.get("Message", ""), None)
    else:
        return None, None, None, resp


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssumeRoleWithWebIdentity with a garbage token is rejected 400 InvalidIdentityToken for
    both a nonexistent and an existing role, unlike AssumeRole's 403 AccessDenied for the
    nonexistent ARN: STS validates the token before resolving the role.
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    missing_role_name = ctx.unique_name("sim2real-behav-no-such-oidc-role-")
    missing_role_arn = f"arn:aws:iam::{account_id}:role/{missing_role_name}"

    # Positive control: AssumeRole's AccessDenied proves the ARN resolves to no role.
    control_code, control_status, control_msg, control_resp = _error(
        lambda: sts.assume_role(
            RoleArn=missing_role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-")
        )
    )
    assert control_code is not None, (
        f"AssumeRole ISSUED CREDENTIALS for a nonexistent role: {control_resp!r}"
    )
    assert control_code == "AccessDenied" and control_status == 403, (
        f"expected AccessDenied/403 for AssumeRole on a nonexistent role, got "
        f"{control_code!r}/{control_status!r}"
    )
    assert control_msg == (
        f"User: {caller['Arn']} is not authorized to perform: sts:AssumeRole on resource: "
        f"{missing_role_arn}"), f"AssumeRole's nonexistent-role denial message: {control_msg!r}"

    missing_code, missing_status, missing_msg, missing_resp = _error(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=missing_role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            WebIdentityToken=_GARBAGE_TOKEN,
        )
    )
    assert missing_code is not None, (
        f"AssumeRoleWithWebIdentity ISSUED CREDENTIALS for a nonexistent role: {missing_resp!r}"
    )
    assert missing_code == "InvalidIdentityToken" and missing_status == 400, (
        f"expected 400 InvalidIdentityToken for a nonexistent role with a garbage token, got "
        f"{missing_code!r}/{missing_status!r}"
    )
    assert missing_msg == _GARBAGE_TOKEN_MESSAGE, (
        f"the garbage-token refusal message: {missing_msg!r}"
    )
    assert missing_code != control_code, (
        "AssumeRoleWithWebIdentity returned the SAME code as AssumeRole's nonexistent-role "
        f"AccessDenied ({missing_code!r}); expected a token-validation rejection instead, which "
        "is the whole point of this check"
    )

    # An existing role with an unrelated trust policy gets the identical rejection, so it is
    # driven by the token, not by role existence.
    real_role_name = ctx.unique_name("sim2real-behav-plain-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    real_role_arn = iam.create_role(
        RoleName=real_role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.delete_role(RoleName=real_role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_delete_role)

    existing_code, existing_status, existing_msg, existing_resp = _error(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=real_role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            WebIdentityToken=_GARBAGE_TOKEN,
        )
    )
    assert existing_code is not None, (
        "AssumeRoleWithWebIdentity ISSUED CREDENTIALS against a role with an unrelated trust "
        f"policy: {existing_resp!r}"
    )
    assert (existing_code, existing_status, existing_msg) == (missing_code, missing_status,
                                                              _GARBAGE_TOKEN_MESSAGE), (
        f"expected the EXISTING-but-unrelated-role case to produce the identical "
        f"{missing_code!r}/{missing_status!r} the nonexistent-role case did (proving the "
        f"rejection tracks the token, not role existence), got "
        f"{existing_code!r}/{existing_status!r}: {existing_msg!r}"
    )

    retry_code, retry_status, retry_msg, _ = _error(
        lambda: sts.assume_role_with_web_identity(
            RoleArn=missing_role_arn,
            RoleSessionName=ctx.unique_name("sim2real-behav-sess-"),
            WebIdentityToken=_GARBAGE_TOKEN,
        )
    )
    assert (retry_code, retry_status, retry_msg) == (
        "InvalidIdentityToken", 400, _GARBAGE_TOKEN_MESSAGE), (
        f"the retried call answered {retry_code!r}/{retry_status!r}: {retry_msg!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
