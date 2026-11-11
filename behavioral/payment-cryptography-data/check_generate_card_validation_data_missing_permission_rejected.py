"""generate-card-validation-data-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-card-validation-data-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography-data"]

PAN = "471234567890123"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no policies gets AccessDeniedException with its exact message from
    GenerateCardValidationData on a key the caller can use, and after a policy granting that action is
    attached the role's call returns the same ValidationData as the caller's."""
    key = _create_cvk(ctx)
    data = ctx.client("payment-cryptography-data")
    gen_attrs = {"CardVerificationValue1": {"CardExpiryDate": "1127", "ServiceCode": "121"}}
    call_kwargs = dict(
        KeyIdentifier=key["arn"], PrimaryAccountNumber=PAN, GenerationAttributes=gen_attrs
    )

    # Positive control: the caller's own credentials are permitted.
    control_resp = data.generate_card_validation_data(**call_kwargs)

    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-noaccess-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sim2real-behav-sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name)
    restricted = ctx.client(
        "payment-cryptography-data",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # Break exactly one thing: the assumed role has no attached policy at all, so the
    # identical call is refused by implicit deny. A freshly minted session can bounce
    # InvalidClientTokenId for a moment before STS propagates it -- that is credential
    # propagation, not the authorization outcome under test, so it is retried rather
    # than mistaken for the answer.
    err = _poll_denial(
        lambda: restricted.generate_card_validation_data(**call_kwargs),
        timeout_s=20.0,
    )
    assert err is not None, "an implicit-deny role must not be able to generate CVV data"
    assert err.response["Error"]["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for the implicit-deny role, got "
        f"{err.response['Error']['Code']!r}"
    )
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: payment-cryptography:GenerateCardValidationData on resource: "
        f"{key['arn']} because no identity-based policy allows the "
        f"payment-cryptography:GenerateCardValidationData action"
    )
    msg = err.response["Error"]["Message"]
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Restore: grant the SAME role the one permission it lacked, on the SAME session
    # credentials (IAM evaluates authorization per-request, not per-session-mint, so no
    # re-assume is needed), and demand the identical call now succeeds -- proving the
    # denial above was this permission's absence, not the key, the PAN or the attributes.
    restore_policy_name = "sim2real-generate-cvv-allow"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=restore_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        # Real AWS's own AccessDeniedException names this action under the
                        # "payment-cryptography" IAM prefix, not "payment-cryptography-data"
                        # (the boto3/endpoint service id).
                        "Effect": "Allow",
                        "Action": "payment-cryptography:GenerateCardValidationData",
                        "Resource": key["arn"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=restore_policy_name)
    )

    restored_resp = _poll_until_success(
        lambda: restricted.generate_card_validation_data(**call_kwargs),
        timeout_s=240.0,
        description="the granted policy becomes effective for GenerateCardValidationData",
    )
    assert restored_resp["ValidationData"] == control_resp["ValidationData"], (
        "the identical key/PAN/attributes must produce the identical CVV once the role is "
        f"granted the permission it lacked; control={control_resp['ValidationData']!r} "
        f"restored={restored_resp['ValidationData']!r}"
    )


_CREDENTIAL_PROPAGATION = frozenset({"InvalidClientTokenId", "SignatureDoesNotMatch"})


def _poll_denial(fn, *, timeout_s, interval_s=2.0):
    """The ClientError from fn(), retrying only credential-propagation codes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _CREDENTIAL_PROPAGATION or time.monotonic() >= deadline:
                return exc
            time.sleep(interval_s)


def _poll_until_success(fn, *, timeout_s, description, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"{description} not reached within {timeout_s}s; last error {last_exc!r}"
    )


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=25.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    raise last_exc


def _create_cvk(ctx):
    pc = ctx.client("payment-cryptography")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_C0_CARD_VERIFICATION_KEY",
            "KeyModesOfUse": {"Generate": True, "Verify": True},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    key = resp["Key"]
    arn = key["KeyArn"]

    def _cleanup():
        try:
            pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": arn, "kcv": key["KeyCheckValue"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
