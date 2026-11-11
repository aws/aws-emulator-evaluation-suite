"""grant-name-idempotency-and-revoke-semantics."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "grant-name-idempotency-and-revoke-semantics"
GROUP = 'grants'
SERVICES = ['kms']

ERR_NOT_FOUND = "NotFoundException"


def _client_error(fn):
    """Call fn(); return its botocore Error. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is true; raise AssertionError on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


def _teardown_key(kms, key_arn: str) -> None:
    """Schedule deletion of a CMK this check minted (7-day minimum window; bills until then)."""
    assert key_arn.startswith("arn:") and ":key/" in key_arn, key_arn
    assert "alias/" not in key_arn, key_arn
    kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


def _grant_ids(kms, key_arn: str) -> set:
    """Fully paginate ListGrants for one key and return the set of GrantIds."""
    ids, marker, pages = set(), None, 0
    while pages < 20:
        pages += 1
        page = kms.list_grants(**({"Marker": marker} if marker else {}), KeyId=key_arn)
        ids.update(g["GrantId"] for g in page.get("Grants", []))
        if not page.get("Truncated"):
            return ids
        marker = page["NextMarker"]
    raise AssertionError("ListGrants did not terminate within 20 pages")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Replaying a named CreateGrant returns the same GrantId and adds no grant, while the same Name with
    different Operations creates a new grant and leaves the first unchanged; a second RevokeGrant of the same
    grant fails with NotFoundException and the exact message, and the key stays Enabled and decrypts."""
    kms = ctx.client("kms")
    grantee = f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:root"
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-grantidem-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_arn = meta["Arn"]
    ctx.on_cleanup(lambda _a=key_arn: _teardown_key(kms, _a))

    plaintext = b"grant-idempotency-probe"
    ct = kms.encrypt(KeyId=key_arn, Plaintext=plaintext)["CiphertextBlob"]
    assert _grant_ids(kms, key_arn) == set(), "a fresh key must have no grants"

    name = "sim2realBehavGrantIdem"
    ops = ["Decrypt", "GenerateDataKey"]
    first = kms.create_grant(
        KeyId=key_arn, GranteePrincipal=grantee, Operations=ops, Name=name
    )
    grant_id = first["GrantId"]
    assert grant_id, first
    assert first.get("GrantToken"), first

    # --- Idempotency: byte-identical replay. Same GrantId, still exactly one grant.
    replay = kms.create_grant(
        KeyId=key_arn, GranteePrincipal=grantee, Operations=ops, Name=name
    )
    assert replay["GrantId"] == grant_id, (
        f"an identical named CreateGrant must return the same GrantId; "
        f"got {replay['GrantId']!r} vs {grant_id!r}"
    )
    assert _grant_ids(kms, key_arn) == {grant_id}, _grant_ids(kms, key_arn)

    # Operations order must not make the request non-identical — it is a set, not a list.
    reordered = kms.create_grant(
        KeyId=key_arn, GranteePrincipal=grantee, Operations=list(reversed(ops)), Name=name
    )
    assert reordered["GrantId"] == grant_id, (
        f"Operations order must not affect named idempotency; got {reordered['GrantId']!r}"
    )

    # --- Same Name, different Operations: not a retry, so KMS creates a NEW grant (CreateGrant's
    # Name is idempotent only for identical parameters) and leaves the first one untouched.
    other = kms.create_grant(
        KeyId=key_arn, GranteePrincipal=grantee, Operations=["Encrypt"], Name=name
    )["GrantId"]
    assert other != grant_id, (
        f"the same grant Name with different Operations must yield a new GrantId, got {other!r}"
    )
    _poll_until(
        lambda: _grant_ids(kms, key_arn),
        lambda ids: ids == {grant_id, other},
        timeout_s=60,
        description="ListGrants to show both grants",
    )
    single = kms.list_grants(KeyId=key_arn, GrantId=grant_id)["Grants"]
    assert len(single) == 1, single
    got = single[0]
    assert got["GrantId"] == grant_id, got
    assert got["Name"] == name, got
    assert got["GranteePrincipal"] == grantee, got
    assert set(got["Operations"]) == set(ops), (
        f"the second CreateGrant must not have rewritten the first grant's Operations; "
        f"got {got['Operations']!r}"
    )
    assert got["KeyId"] == key_arn, got
    kms.revoke_grant(KeyId=key_arn, GrantId=other)

    # --- RevokeGrant removes it, and the removal is observable in ListGrants.
    kms.revoke_grant(KeyId=key_arn, GrantId=grant_id)
    _poll_until(
        lambda: _grant_ids(kms, key_arn),
        lambda ids: not ids & {grant_id, other},
        timeout_s=60,
        description="the revoked grants to disappear from ListGrants",
    )

    # --- RevokeGrant is NOT idempotent: the second call fails. An emulator returning 200 for a
    # no-op revoke hides a real client bug.
    # RevokeGrant models NotFoundException and InvalidGrantIdException; a well-formed id of an
    # already-revoked grant answers NotFoundException.
    err = _client_error(lambda: kms.revoke_grant(KeyId=key_arn, GrantId=grant_id))
    assert err["Code"] == ERR_NOT_FOUND, (
        f"revoking an already-revoked grant must raise {ERR_NOT_FOUND}, got {err!r}"
    )
    expected = f"Grant ID {grant_id} not found"
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # --- Control: the key itself is untouched by all of the above. Recreating the revoked
    # Encrypt grant under the same Name succeeds and, measured on real AWS, returns that grant's
    # old GrantId: KMS derives a named grant's id from its parameters.
    decrypted = kms.decrypt(CiphertextBlob=ct, KeyId=key_arn)["Plaintext"]
    assert decrypted == plaintext, f"the key must still decrypt correctly; got {decrypted!r}"
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"the key must remain Enabled throughout; got {state!r}"
    reused = kms.create_grant(
        KeyId=key_arn, GranteePrincipal=grantee, Operations=["Encrypt"], Name=name
    )
    assert reused["GrantId"] == other, (
        f"recreating the revoked Encrypt grant must return its GrantId {other!r}, got {reused['GrantId']!r}"
    )
    ctx.on_cleanup(
        lambda _a=key_arn, _g=reused["GrantId"]: kms.revoke_grant(KeyId=_a, GrantId=_g)
    )
    assert _grant_ids(kms, key_arn) == {reused["GrantId"]}, _grant_ids(kms, key_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
