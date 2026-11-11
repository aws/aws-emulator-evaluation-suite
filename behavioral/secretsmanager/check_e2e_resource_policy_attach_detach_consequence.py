"""e2e-resource-policy-attach-detach-consequence."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-resource-policy-attach-detach-consequence"
GROUP = "server-side"
SERVICES = ["secretsmanager"]

_SESSION_NAME = "sim2real-behav-secondprincipal"

_CREDENTIAL_PROPAGATION = frozenset({"UnrecognizedClientException", "InvalidClientTokenId", "SignatureDoesNotMatch"})


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Attaching a resource-policy Allow is the ONLY thing that grants a principal with zero
    identity-based permissions read access to a secret; detaching it revokes that access again,
    while the owner's own access is unaffected throughout.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-secmgr-respolicy-")
    created = sm.create_secret(
        Name=name, SecretString="policy-test-value", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    # A policy granting the account root would be inert (root already has access), so the effect
    # is observed on a role with an empty identity policy and no other path to the secret.
    role_arn = _create_second_principal_role(ctx, iam, account_id)
    as_second = _client_for_credentials(ctx, *_assume(sts, role_arn))
    partition = role_arn.split(":")[1]
    session_arn = (
        f"arn:{partition}:sts::{account_id}:assumed-role/{role_arn.split('/')[-1]}/{_SESSION_NAME}"
    )
    no_grant = (
        "error",
        "AccessDeniedException",
        f"User: {session_arn} is not authorized to perform: secretsmanager:GetSecretValue on "
        f"resource: {secret_arn} because no identity-based policy allows the "
        "secretsmanager:GetSecretValue action",
    )

    # Baseline: no resource policy attached yet, and owner access works.
    baseline = sm.get_resource_policy(SecretId=secret_arn)
    assert "ResourcePolicy" not in baseline, f"a fresh secret must have no resource policy, got {baseline}"
    owner_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert owner_value == "policy-test-value", f"owner baseline read mismatch: {owner_value!r}"

    # The second principal has NO identity-based grant and no resource policy either: denied.
    # Freshly-minted STS credentials can take a few seconds to propagate; a signing failure
    # (UnrecognizedClientException / InvalidClientTokenId) means the credentials are not yet
    # live everywhere, not that the request was evaluated, so it is not the answer under test.
    denied_before = _poll(
        lambda: _probe(as_second, secret_arn),
        lambda r: r[1] not in _CREDENTIAL_PROPAGATION,
        timeout_s=30.0,
        interval_s=2.0,
        description="the assumed-role credentials become recognized (STS propagation)",
    )
    assert denied_before == no_grant, (
        f"a role with no identity policy and no resource policy must be denied before any policy "
        f"is attached; got {denied_before}"
    )

    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    _put_resource_policy_with_retry(sm, secret_arn, allow_policy)

    attached = json.loads(sm.get_resource_policy(SecretId=secret_arn)["ResourcePolicy"])
    attached_principal = attached["Statement"][0]["Principal"]["AWS"]
    assert attached_principal == role_arn, f"stored policy names {attached_principal!r}, expected {role_arn!r}"

    # Owner access must remain unaffected while the policy is attached.
    owner_during = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert owner_during == "policy-test-value", f"owner read mismatch while policy attached: {owner_during!r}"

    # The ONLY grant this second principal has ever had is the resource policy just attached, so
    # its read succeeding is the resource policy's effect and nothing else.
    granted = _poll(
        lambda: _probe(as_second, secret_arn),
        lambda r: r[0] == "ok",
        timeout_s=60.0,
        interval_s=3.0,
        description="the Allow resource policy becomes effective for the second principal",
    )
    assert granted == ("ok", "policy-test-value"), (
        f"the Allow resource policy naming this role must grant it read access; got {granted}"
    )

    sm.delete_resource_policy(SecretId=secret_arn)

    after_removal = sm.get_resource_policy(SecretId=secret_arn)
    assert "ResourcePolicy" not in after_removal, f"policy must be gone after delete, got {after_removal}"

    # Owner access must still work after the policy is removed.
    owner_after = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert owner_after == "policy-test-value", f"owner read mismatch after policy removed: {owner_after!r}"

    # Revoking the sole grant must revoke the second principal's access again.
    denied_after = _poll(
        lambda: _probe(as_second, secret_arn),
        lambda r: r[0] == "error",
        timeout_s=60.0,
        interval_s=3.0,
        description="removing the resource policy revokes the second principal's only grant",
    )
    assert denied_after == no_grant, (
        f"deleting the resource policy must deny the second principal again; got {denied_after}"
    )


def _create_second_principal_role(ctx, iam, account_id):
    """A role with NO identity-based permissions -- its only possible grant to the secret is
    whatever resource policy names it."""
    role_name = ctx.unique_name("sim2real-behav-secmgr-secondprincipal-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Role"]["Arn"]


def _assume(sts, role_arn, timeout_s=60.0, interval_s=3.0):
    """Assume the freshly-created role, retrying while its trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            return creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "AccessDenied":
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"assume-role never succeeded (trust policy propagation?): {last_err}")


def _client_for_credentials(ctx, access_key_id, secret_access_key, session_token):
    """A secretsmanager client signing AS the minted second principal, not the harness identity."""
    return ctx.client(
        "secretsmanager",
        creds={
            "aws_access_key_id": access_key_id,
            "aws_secret_access_key": secret_access_key,
            "aws_session_token": session_token,
        },
    )


def _probe(client, secret_id):
    """(\"ok\", value) on success, (\"error\", code, message) on a ClientError."""
    try:
        return ("ok", client.get_secret_value(SecretId=secret_id)["SecretString"])
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return ("error", error.get("Code"), error.get("Message"))


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _put_resource_policy_with_retry(sm, secret_arn, policy, timeout_s=60.0, interval_s=3.0):
    """Secrets Manager resolves the policy's Principal ARN against IAM when the policy is
    attached; a role created moments earlier may not have propagated yet, which surfaces as
    MalformedPolicyDocumentException even though the JSON itself is well-formed."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            sm.put_resource_policy(SecretId=secret_arn, ResourcePolicy=json.dumps(policy))
            return
        except sm.exceptions.MalformedPolicyDocumentException as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"put_resource_policy never succeeded (principal propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
