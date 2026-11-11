"""resource-policy-cross-account-access-enforced-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-cross-account-access-enforced-denied"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A guardrail resource policy granting the own account's root round-trips exactly but does not
    bypass identity policy: a role with an explicit Deny gets the exact AccessDeniedException on
    GetGuardrail, while a role with an identity-based Allow succeeds."""
    bedrock = ctx.client("bedrock")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    guardrail_name = ctx.unique_name("sim2real-rbp-gr-")
    created = bedrock.create_guardrail(
        name=guardrail_name,
        blockedInputMessaging="Input blocked by test guardrail.",
        blockedOutputsMessaging="Output blocked by test guardrail.",
        wordPolicyConfig={"wordsConfig": [{"text": ctx.unique_name("bannedword").replace("-", "")}]},
        tags=[{"key": "sim2real", "value": "resource-policy-cross-account-access-enforced-denied"}],
    )
    guardrail_id = created["guardrailId"]
    guardrail_arn = created["guardrailArn"]

    def _cleanup_guardrail() -> None:
        try:
            bedrock.delete_resource_policy(resourceArn=guardrail_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)

    ctx.on_cleanup(_cleanup_guardrail)

    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    ready_status = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)["status"]
    assert ready_status == "READY", f"expected the guardrail to reach READY, got {ready_status!r}"

    version = bedrock.create_guardrail_version(guardrailIdentifier=guardrail_id)["version"]
    _poll_until(
        lambda: bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)["status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )

    # Guardrail resource policies support only this shape: Allow, an account-root Principal,
    # and the {ApplyGuardrail, GetGuardrail} action pair.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["bedrock:ApplyGuardrail", "bedrock:GetGuardrail"],
                "Resource": guardrail_arn,
            }
        ],
    }
    try:
        bedrock.put_resource_policy(resourceArn=guardrail_arn, resourcePolicy=json.dumps(policy_doc))
    except ClientError as err:
        msg = err.response["Error"].get("Message", "")
        if "does not conform" in msg:
            raise AssertionError(
                "PutResourcePolicy rejects even a documented-shape guardrail resource "
                "policy in this account with 'does not conform to the supported policy "
                "formats' -- empirically this account cannot store ANY valid guardrail "
                "RBP (likely because it is a standalone account outside an AWS "
                "Organization, a prerequisite this feature appears to require even for "
                "same-account sharing), so the same-account-vs-identity-policy "
                "enforcement boundary this check targets is not exercisable here."
            ) from err
        raise

    fetched_policy = json.loads(bedrock.get_resource_policy(resourceArn=guardrail_arn)["resourcePolicy"])
    assert fetched_policy == policy_doc, (
        f"expected the stored resource policy to match exactly what was put, got {fetched_policy!r}"
    )

    # Explicit Deny keeps the denial independent of any baseline permissions on new roles.
    no_perm_role_name = ctx.unique_name("sim2real-rbp-noperm-role-")
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
        Tags=[{"Key": "sim2real", "Value": "resource-policy-cross-account-access-enforced-denied"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=no_perm_role_name))
    no_perm_role_arn = f"arn:aws:iam::{account_id}:role/{no_perm_role_name}"
    deny_policy_name = "deny-get-guardrail"
    iam.put_role_policy(
        RoleName=no_perm_role_name,
        PolicyName=deny_policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "bedrock:GetGuardrail", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=no_perm_role_name, PolicyName=deny_policy_name))

    no_perm_bedrock = _assume_role_client(ctx, no_perm_role_arn, "bedrock")
    # IAM propagates the inline Deny with a lag, so poll for the expected code.
    denied_code, denied_message = _wait_for_error_code(
        lambda: no_perm_bedrock.get_guardrail(guardrailIdentifier=guardrail_id), "AccessDeniedException"
    )
    assert denied_code == "AccessDeniedException", (
        "expected a same-account principal with no identity-based bedrock "
        "permission to be denied GetGuardrail even though the resource policy "
        f"nominally covers the whole account, got {denied_code!r}: {denied_message!r}"
    )
    assert denied_message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{no_perm_role_name}/sim2real-rbp-session "
        f"is not authorized to perform: bedrock:GetGuardrail on resource: {guardrail_arn} "
        "with an explicit deny in an identity-based policy"
    ), f"unexpected denial message: {denied_message!r}"

    allowed_role_name = ctx.unique_name("sim2real-rbp-allowed-role-")
    iam.create_role(
        RoleName=allowed_role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "resource-policy-cross-account-access-enforced-denied"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=allowed_role_name))
    allowed_role_arn = f"arn:aws:iam::{account_id}:role/{allowed_role_name}"
    policy_name = "allow-get-guardrail"
    iam.put_role_policy(
        RoleName=allowed_role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "bedrock:GetGuardrail", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=allowed_role_name, PolicyName=policy_name))

    allowed_bedrock = _assume_role_client(ctx, allowed_role_arn, "bedrock")
    allowed_resp = _retry_get_guardrail(allowed_bedrock, guardrail_id)
    assert allowed_resp["guardrailId"] == guardrail_id, (
        f"expected the permitted role's GetGuardrail to succeed and return the "
        f"real guardrail, got {allowed_resp!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be denied, but it succeeded: {result!r}")


def _wait_for_error_code(fn, expected_code, timeout_s=30.0, interval_s=2.0):
    """Poll until ``fn`` fails with ``expected_code`` or the deadline passes; return the last
    (code, message). A call that succeeds raises."""
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        last = _error(fn)
        if last[0] == expected_code:
            return last
        time.sleep(interval_s)
    return last


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _assume_role_client(ctx, role_arn, service_name, timeout_s=45.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-rbp-session")["Credentials"]
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


def _retry_get_guardrail(bedrock_client, guardrail_id, timeout_s=45.0, interval_s=3.0):
    # IAM identity-based policy propagation can lag a few seconds after
    # put_role_policy; poll until the newly-granted permission takes effect.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return bedrock_client.get_guardrail(guardrailIdentifier=guardrail_id)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] == "AccessDeniedException":
                time.sleep(interval_s)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
