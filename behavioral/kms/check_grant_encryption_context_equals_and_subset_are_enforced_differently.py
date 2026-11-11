"""grant-encryption-context-equals-and-subset-are-enforced-differently."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "grant-encryption-context-equals-and-subset-are-enforced-differently"
GROUP = "grants"
SERVICES = ["kms"]

ERR_ACCESS_DENIED = "AccessDeniedException"
_BASE = {"tenant": "acme", "purpose": "invoice"}
_SUPERSET = {"tenant": "acme", "purpose": "invoice", "extra": "audit"}
_STRICT_SUBSET = {"tenant": "acme"}
_PLAINTEXT = b"grant-constraint-differential-plaintext"


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7 days is the AWS minimum window)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    for attempt in range(4):
        try:
            kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "KMSInvalidStateException":
                return
            if code not in ("ThrottlingException", "KMSInternalException") or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))


def _revoke_grant(kms, key_arn: str, grant_id: str) -> None:
    """Revoke a grant this check created, tolerating only NotFoundException.

    The body revokes one grant itself, so a second revoke of that id is expected."""
    try:
        kms.revoke_grant(KeyId=key_arn, GrantId=grant_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _delete_role(iam, role_name: str) -> None:
    """Delete the bare role this check created. Tolerates ONLY NoSuchEntity."""
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _create_bare_role(ctx) -> tuple[str, str]:
    """An IAM role trusted only by the calling account, with NO attached or inline policies — its
    sole potential source of KMS permission in this check is a grant naming it directly."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-kmsgrantdiff-role-")
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
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "kms-grant-constraint-differential"}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    return created["Role"]["Arn"], role_name


def _assumed_role_client(ctx, role_arn: str, service: str) -> Any:
    """Assume role_arn (retrying past IAM's eventual-consistency window) and build a client from
    ONLY those temporary credentials, with no fallback to ctx's own creds.
    """
    sts = ctx.client("sts")
    deadline = time.monotonic() + 30.0
    last_err: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)
            break
        except ClientError as err:  # role not yet assumable everywhere
            last_err = err
            time.sleep(2.0)
    if resp is None:
        raise AssertionError(f"could not assume role {role_arn} within 30s: {last_err}")
    creds = resp["Credentials"]
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _create_grant_with_retry(kms, *, key_arn, role_arn, constraints, timeout_s=60.0):
    """CreateGrant validates GranteePrincipal against IAM, which is eventually consistent — a role
    created moments ago may briefly be invisible to KMS. Retry past that window, then RAISE."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return kms.create_grant(
                KeyId=key_arn,
                GranteePrincipal=role_arn,
                Operations=["Encrypt"],
                Constraints=constraints,
            )
        except ClientError as err:  # InvalidArnException while the IAM role propagates
            last_err = err
            time.sleep(2.0)
    raise AssertionError(f"create_grant never succeeded for {role_arn} in {timeout_s}s: {last_err}")


_SESSION_NAME = "sim2real-kms-grantdiff"


def _denied(role_arn: str, key_arn: str) -> str:
    """The AccessDeniedException message KMS returns to the role's session for Encrypt on key_arn."""
    account, role_path = role_arn.split(":")[4], role_arn.split(":")[5]
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_path.split('/')[-1]}/{_SESSION_NAME}"
    return (
        f"User: {session_arn} is not authorized to perform: kms:Encrypt on resource: {key_arn} "
        f"because no identity-based policy allows the kms:Encrypt action"
    )


def _encrypt_outcome(grantee_kms, key_arn: str, context: dict, grant_token: str | None):
    """Return (None, CiphertextBlob, None) on success or (Error.Code, None, Error.Message) on refusal.

    GrantTokens is omitted when grant_token is None: botocore refuses a zero-length token locally.
    """
    kwargs = {"KeyId": key_arn, "Plaintext": _PLAINTEXT, "EncryptionContext": context}
    if grant_token is not None:
        kwargs["GrantTokens"] = [grant_token]
    try:
        resp = grantee_kms.encrypt(**kwargs)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), None, err.get("Message")
    return None, resp["CiphertextBlob"], None


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A context that is a strict superset of the constraint is allowed by a Subset grant and refused
    by an Equals grant; the exact context passes both, a strict subset fails both (AccessDenied).

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_GrantConstraints.html
    """
    kms = ctx.client("kms")
    role_arn, _role_name = _create_bare_role(ctx)
    grantee = _assumed_role_client(ctx, role_arn, "kms")

    def new_key(label: str) -> str:
        meta = kms.create_key(
            Description=ctx.unique_name(f"sim2real-behav-kms-grantdiff-{label}-"),
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Tags=[{"TagKey": "sim2real", "TagValue": "kms-grant-constraint-differential"}],
        )["KeyMetadata"]
        ctx.on_cleanup(lambda _a=meta["Arn"]: _teardown_key(kms, _a))
        return meta["Arn"]

    def grant_on(key_arn: str, constraints: dict) -> str:
        grant = _create_grant_with_retry(
            kms, key_arn=key_arn, role_arn=role_arn, constraints=constraints
        )
        grant_id = grant["GrantId"]
        ctx.on_cleanup(lambda _a=key_arn, _g=grant_id: _revoke_grant(kms, _a, _g))
        echoed = kms.list_grants(KeyId=key_arn, GrantId=grant_id)["Grants"]
        assert len(echoed) == 1, (
            f"ListGrants must return exactly the one grant {grant_id!r} on {key_arn!r}, got "
            f"{echoed!r}"
        )
        assert echoed[0]["Constraints"] == constraints, (
            f"the stored constraint must be what was asked for: expected {constraints!r}, got "
            f"{echoed[0]['Constraints']!r}"
        )
        return grant["GrantToken"]

    key_equals = new_key("eq")
    key_subset = new_key("sub")
    key_control = new_key("ctl")

    # Without a grant the bare role has no permission on a KMS key, so every allow below is
    # evidence that the grant did something.
    code, blob, message = _encrypt_outcome(grantee, key_control, _BASE, None)
    assert blob is None and code == ERR_ACCESS_DENIED, (
        f"a bare IAM role with no policy must be refused Encrypt on an ungranted key with "
        f"{ERR_ACCESS_DENIED} — otherwise the grants below prove nothing; got code {code!r}"
    )
    assert message == _denied(role_arn, key_control), f"unexpected message: {message!r}"

    token_equals = grant_on(key_equals, {"EncryptionContextEquals": _BASE})
    token_subset = grant_on(key_subset, {"EncryptionContextSubset": _BASE})

    # --- Positive control, both kinds, identical request: the EXACT context is allowed.
    for label, key_arn, token in (
        ("Equals", key_equals, token_equals),
        ("Subset", key_subset, token_subset),
    ):
        code, blob, _msg = _encrypt_outcome(grantee, key_arn, _BASE, token)
        assert code is None and blob is not None, (
            f"positive control: the {label} grant must allow Encrypt with the exact constraint "
            f"context {_BASE!r}; got code {code!r}"
        )

    # --- THE DIFFERENTIAL, same instant, same principal, same plaintext, superset context.
    code_subset, subset_blob, _msg = _encrypt_outcome(grantee, key_subset, _SUPERSET, token_subset)
    assert code_subset is None and subset_blob is not None, (
        f"EncryptionContextSubset must ALLOW a request context that adds pairs beyond the "
        f"constraint: constraint {_BASE!r}, request {_SUPERSET!r}, got code {code_subset!r}"
    )
    code_equals, equals_blob, message_equals = _encrypt_outcome(grantee, key_equals, _SUPERSET, token_equals)
    assert equals_blob is None, (
        f"EncryptionContextEquals must REFUSE a request context that adds pairs beyond the "
        f"constraint: constraint {_BASE!r}, request {_SUPERSET!r} was accepted"
    )
    assert code_equals == ERR_ACCESS_DENIED, (
        f"the Equals constraint violation must be {ERR_ACCESS_DENIED} (an authorization refusal, "
        f"not input validation); got {code_equals!r}"
    )
    assert message_equals == _denied(role_arn, key_equals), f"unexpected message: {message_equals!r}"

    # --- The other direction: a STRICT SUBSET of the constraint is refused by BOTH kinds, because
    # Subset requires the constraint to be contained in the request, not the reverse.
    for label, key_arn, token in (
        ("Equals", key_equals, token_equals),
        ("Subset", key_subset, token_subset),
    ):
        code, blob, message = _encrypt_outcome(grantee, key_arn, _STRICT_SUBSET, token)
        assert blob is None, (
            f"the {label} grant must refuse a request context {_STRICT_SUBSET!r} that DROPS a "
            f"required pair from {_BASE!r}"
        )
        assert code == ERR_ACCESS_DENIED, (
            f"the {label} grant's refusal of the dropped-pair context must be "
            f"{ERR_ACCESS_DENIED}; got {code!r}"
        )
        assert message == _denied(role_arn, key_arn), f"unexpected message: {message!r}"

    # --- Restore beat: change only the constraint KIND on the Equals key and the identical
    # superset call must now succeed. This is what separates "Equals is enforced" from "this key
    # refuses supersets for some other reason".
    equals_grants = kms.list_grants(KeyId=key_equals)["Grants"]
    mine = [g for g in equals_grants if g.get("GranteePrincipal") == role_arn]
    assert len(mine) == 1, (
        f"exactly one grant on {key_equals!r} must name {role_arn!r}, got {mine!r}"
    )
    kms.revoke_grant(KeyId=key_equals, GrantId=mine[0]["GrantId"])
    relaxed_token = grant_on(key_equals, {"EncryptionContextSubset": _BASE})
    code, relaxed_blob, _msg = _encrypt_outcome(grantee, key_equals, _SUPERSET, relaxed_token)
    assert code is None and relaxed_blob is not None, (
        f"after replacing the Equals constraint with an identical-map Subset constraint on the "
        f"SAME key, the byte-identical superset request must succeed; got code {code!r}"
    )

    # --- Terminal independent read at the destination, via a DIFFERENT operation than the
    # mutation: the account owner decrypts what the grantee produced through the Subset path.
    dec = kms.decrypt(CiphertextBlob=subset_blob, EncryptionContext=_SUPERSET)
    assert dec["Plaintext"] == _PLAINTEXT, (
        f"the ciphertext the grantee produced under the Subset grant must decrypt to the exact "
        f"plaintext; expected {_PLAINTEXT!r}, got {dec['Plaintext']!r}"
    )
    assert dec["KeyId"] == key_subset, (
        f"the blob must resolve to {key_subset!r}, got {dec['KeyId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
