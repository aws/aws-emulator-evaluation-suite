"""retire-grant-and-list-retirable."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "retire-grant-and-list-retirable"
GROUP = 'grants'
SERVICES = ['kms']


def _account_root_arn(key_arn: str) -> str:
    """Derive the account-root principal ARN from a KMS key ARN.

    The account id is the 5th ``:``-delimited field of
    ``arn:aws:kms:<region>:<account>:key/<id>``.
    """
    return f"arn:aws:iam::{key_arn.split(':')[4]}:root"


def _create_bare_role(ctx) -> str:
    """A real IAM role, trusted only by the calling account, to use as GranteePrincipal --
    CreateGrant validates the ARN refers to an actual principal (InvalidArnException otherwise)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-kms-retire-grantee-")
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
    created = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = created["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_arn


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_grant_with_retry(kms, *, key_id, grantee, retiring, operations, timeout_s=20.0):
    """CreateGrant validates GranteePrincipal against IAM, which is eventually consistent -- a
    role created moments ago may briefly be invisible to KMS. Retry past that window."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return kms.create_grant(
                KeyId=key_id,
                GranteePrincipal=grantee,
                RetiringPrincipal=retiring,
                Operations=operations,
            )
        except Exception as err:  # InvalidArnException while the IAM role propagates
            last_err = err
            time.sleep(2.0)
    raise AssertionError(f"create_grant never succeeded for grantee {grantee}: {last_err}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A grant with a RetiringPrincipal is discoverable via ListRetirableGrants and removable via RetireGrant."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("kms-retire-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    grantee = _create_bare_role(ctx)
    retiring = _account_root_arn(meta["Arn"])

    grant = _create_grant_with_retry(
        kms, key_id=key_id, grantee=grantee, retiring=retiring, operations=["Encrypt"]
    )
    grant_id = grant["GrantId"]

    def _all_retirable():
        out, marker = [], None
        while True:
            kwargs = {"RetiringPrincipal": retiring, "Limit": 100}
            if marker:
                kwargs["Marker"] = marker
            page = kms.list_retirable_grants(**kwargs)
            out.extend(page["Grants"])
            if not page.get("Truncated"):
                return out
            marker = page["NextMarker"]

    listed = _poll_until(
        _all_retirable,
        lambda gs: any(g["GrantId"] == grant_id for g in gs),
        timeout_s=90,
        description="grant appears in ListRetirableGrants",
    )
    assert listed, "grant with a RetiringPrincipal must appear in ListRetirableGrants"
    entry = next(g for g in listed if g["GrantId"] == grant_id)
    assert entry["RetiringPrincipal"] == retiring, entry["RetiringPrincipal"]
    assert entry["KeyId"] == meta["Arn"], entry["KeyId"]

    kms.retire_grant(KeyId=meta["Arn"], GrantId=grant_id)

    gone = _poll_until(
        lambda: [g["GrantId"] for g in kms.list_grants(KeyId=key_id)["Grants"]],
        lambda ids: grant_id not in ids,
        timeout_s=60,
        description="retired grant disappears from ListGrants",
    )
    assert grant_id not in gone, "retired grant must disappear from ListGrants"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
