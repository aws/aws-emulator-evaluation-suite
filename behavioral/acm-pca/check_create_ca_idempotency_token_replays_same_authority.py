"""create-ca-idempotency-token-replays-same-authority."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "create-ca-idempotency-token-replays-same-authority"
GROUP = 'lifecycle'
SERVICES = ['acm-pca']

_MIN_DELETION_DAYS = 7
# IdempotencyToken is modeled length 1..36 in the acm-pca Smithy model; a 36-character
# token exercises the upper bound exactly.
_TOKEN_LEN = 36



def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying teardown: poll out of CREATING, DISABLE if ACTIVE, then DELETE with the
    minimum 7-day window. A delete on a settling CA is refused with InvalidStateException, so this
    retries and RAISES if it still cannot delete, rather than leaking a metered private CA."""
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 300
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError:
            return  # not addressable any more; nothing left to bill
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError:
                pass
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn,
                PermanentDeletionTimeInDays=_MIN_DELETION_DAYS,
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: could not delete certificate authority {ca_arn} within "
        f"300s (last observed Status={last_status!r}). It is STILL BILLING. Delete it "
        f"manually: UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_with_token(ctx, body, token):
    """CreateCertificateAuthority with an explicit idempotency token. Registers teardown for
    whatever ARN comes back BEFORE returning, so a duplicate authority created by a
    non-idempotent implementation is still cleaned up. Retries on throttling."""
    pca = ctx.client("acm-pca")
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(IdempotencyToken=token, **body)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _matching_arns(pca, common_name):
    """Every authority in the account -- including soft-DELETED ones -- whose subject
    CommonName is exactly common_name."""
    found = set()
    paginator = pca.get_paginator("list_certificate_authorities")
    for page in paginator.paginate():
        for ca in page.get("CertificateAuthorities", []):
            subj = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {})
            if subj.get("CommonName") == common_name:
                found.add(ca["Arn"])
    return found


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Replaying CreateCertificateAuthority with the same IdempotencyToken and body returns the same
    ARN and creates no second authority: exactly one CA carries the CommonName, with CreatedAt and
    LastStateChangeAt unchanged by the replay.
    """
    pca = ctx.client("acm-pca")
    timeout_s = 180

    common_name = ctx.unique_name("sim2real-behav-pca-idem-").rstrip("-")
    # No pre-existing authority may carry this CommonName, or the count assertion below
    # would be measuring someone else's resource.
    assert not _matching_arns(pca, common_name), (
        f"CommonName {common_name!r} is already in use in this account"
    )

    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
        "CertificateAuthorityType": "ROOT",
        # The cheaper short-lived tier: the CA is created once and never activated.
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
        "Tags": [{"Key": "sim2real-idem", "Value": "1"}],
    }
    # A 36-character token: the modeled maximum, derived from the unique name so concurrent
    # runs cannot collide.
    token = ctx.unique_name("i").replace("_", "-")[:_TOKEN_LEN].ljust(_TOKEN_LEN, "0")
    assert len(token) == _TOKEN_LEN, token

    arn1 = _create_with_token(ctx, body, token)
    first = _poll_until(
        lambda: _describe(ctx, arn1),
        lambda c: c.get("Status") in ("PENDING_CERTIFICATE", "FAILED"),
        timeout_s=timeout_s, interval_s=2.0,
        description="first CA leaving CREATING",
    )
    assert first["Status"] == "PENDING_CERTIFICATE", (
        f"setup CA did not reach PENDING_CERTIFICATE: {first['Status']!r}"
    )

    # ---- The replay: byte-identical body, identical token ----
    arn2 = _create_with_token(ctx, body, token)
    assert arn2 == arn1, (
        f"replaying CreateCertificateAuthority with the same IdempotencyToken returned a "
        f"DIFFERENT authority.\nfirst:  {arn1}\nsecond: {arn2}\n"
        f"The token was ignored and a second metered private CA was created."
    )

    # ---- Effect absent: no second authority exists ----
    matching = _matching_arns(pca, common_name)
    assert matching == {arn1}, (
        f"expected exactly one authority with CommonName {common_name!r} after the replay, "
        f"found {len(matching)}: {sorted(matching)}"
    )

    # ---- And the replay did not restart or mutate the existing authority ----
    after = _describe(ctx, arn1)
    assert after["Status"] == "PENDING_CERTIFICATE", (
        f"the replay moved the existing authority to {after['Status']!r}; an idempotent "
        f"replay must be a pure read of the prior result"
    )
    assert after["CreatedAt"] == first["CreatedAt"], (
        f"the replay changed CreatedAt from {first['CreatedAt']!r} to "
        f"{after['CreatedAt']!r}; the authority was re-created rather than replayed"
    )
    if "LastStateChangeAt" in first or "LastStateChangeAt" in after:
        assert after.get("LastStateChangeAt") == first.get("LastStateChangeAt"), (
            f"the replay changed LastStateChangeAt from "
            f"{first.get('LastStateChangeAt')!r} to {after.get('LastStateChangeAt')!r}; "
            f"the replay was not side-effect-free"
        )
    # The replay must not have duplicated the tag block either.
    tag_values = [t for t in pca.list_tags(CertificateAuthorityArn=arn1).get("Tags", [])
                  if t["Key"] == "sim2real-idem"]
    assert len(tag_values) == 1, (
        f"the replay duplicated tags on the existing authority: {tag_values}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
