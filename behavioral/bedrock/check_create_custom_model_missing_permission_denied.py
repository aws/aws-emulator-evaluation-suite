"""create-custom-model-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-model-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]

_SESSION_NAME = "sim2real-cm-session"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomModel under an explicit Deny fails with the exact AccessDeniedException and
    creates no model; with bedrock:* granted the same call reaches request validation instead
    (ValidationException for the nonexistent S3 artifact)."""
    bedrock = ctx.client("bedrock")
    iam = ctx.client("iam")
    account_id = ctx.account

    model_name = ctx.unique_name("sim2real-custmodel-")
    bucket_name = f"sim2real-nonexistent-bucket-{model_name}"
    request_kwargs = dict(
        modelName=model_name,
        modelSourceConfig={"s3DataSource": {"s3Uri": f"s3://{bucket_name}/artifacts/"}},
        # Required with an S3 source; omitting it fails validation before IAM is evaluated.
        roleArn=f"arn:aws:iam::{account_id}:role/sim2real-fake-custom-model-role",
    )

    no_perm_role_name = ctx.unique_name("sim2real-nocm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=no_perm_role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=no_perm_role_name))
    no_perm_role_arn = f"arn:aws:iam::{account_id}:role/{no_perm_role_name}"

    # Explicit Deny keeps the denial independent of any baseline permissions on new roles.
    deny_policy_name = "deny-create-custom-model"
    iam.put_role_policy(
        RoleName=no_perm_role_name,
        PolicyName=deny_policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "bedrock:CreateCustomModel", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=no_perm_role_name, PolicyName=deny_policy_name))

    no_perm_bedrock = _assume_role_client(ctx, no_perm_role_arn, "bedrock")

    # The inline Deny policy is eventually consistent, so poll until it is enforced.
    deadline = time.monotonic() + 60.0
    denied_code, denied_msg = _error_code_and_message(
        lambda: no_perm_bedrock.create_custom_model(**request_kwargs)
    )
    while denied_code != "AccessDeniedException" and time.monotonic() < deadline:
        time.sleep(3.0)
        denied_code, denied_msg = _error_code_and_message(
            lambda: no_perm_bedrock.create_custom_model(**request_kwargs)
        )
    assert denied_code == "AccessDeniedException", f"GOT={denied_code!r}"
    # The role also lacks iam:PassRole; the exact message pins the denial to the explicit Deny.
    expected_denied = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{no_perm_role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: bedrock:CreateCustomModel on resource: "
        f"arn:aws:bedrock:{ctx.region}:{account_id}:custom-model/* with an explicit deny in an "
        f"identity-based policy"
    )
    assert denied_msg == expected_denied, f"expected message {expected_denied!r}, got {denied_msg!r}"

    # GetCustomModel on a never-created bare name returns ValidationException, not
    # ResourceNotFoundException.
    lookup_code, lookup_msg = _error_code_and_message(
        lambda: bedrock.get_custom_model(modelIdentifier=model_name)
    )
    assert lookup_code == "ValidationException", f"GOT={lookup_code!r} ({lookup_msg!r})"
    assert lookup_msg == "The provided model identifier is invalid.", f"message={lookup_msg!r}"

    full_perm_role_name = ctx.unique_name("sim2real-cmallowed-role-")
    iam.create_role(
        RoleName=full_perm_role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=full_perm_role_name))
    full_perm_role_arn = f"arn:aws:iam::{account_id}:role/{full_perm_role_name}"
    policy_name = "bedrock-full"
    iam.put_role_policy(
        RoleName=full_perm_role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"},
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": f"arn:aws:iam::{account_id}:role/sim2real-fake-custom-model-role",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=full_perm_role_name, PolicyName=policy_name))

    allowed_bedrock = _assume_role_client(ctx, full_perm_role_arn, "bedrock")
    second_model_name = ctx.unique_name("sim2real-custmodel2-")
    allowed_result: dict = {}

    def _try_allowed_create() -> None:
        allowed_result["response"] = allowed_bedrock.create_custom_model(
            modelName=second_model_name,
            **{k: v for k, v in request_kwargs.items() if k != "modelName"},
        )

    allowed_code, allowed_msg = None, ""
    try:
        _try_allowed_create()
    except ClientError as err:
        allowed_code = err.response["Error"]["Code"]
        allowed_msg = err.response["Error"].get("Message", "")
    else:
        # Avoid leaking a model if the call unexpectedly succeeds.
        ctx.on_cleanup(lambda: bedrock.delete_custom_model(modelIdentifier=second_model_name))
    assert allowed_code == "ValidationException", (allowed_code, allowed_msg)
    expected_allowed = f"Unsupported input passed: '{bucket_name}'."
    assert allowed_msg == expected_allowed, (
        f"expected message {expected_allowed!r}, got {allowed_msg!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assume_role_client(ctx, role_arn, service_name, timeout_s=45.0):
    sts = ctx.client("sts")
    # New roles can be briefly unassumable while IAM propagates; retry AccessDenied.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            return ctx.client(
                service_name,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
                time.sleep(3.0)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
