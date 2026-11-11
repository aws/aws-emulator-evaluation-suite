"""ca-soft-delete-restore-window-and-refused-transitions."""
from __future__ import annotations

import datetime
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "ca-soft-delete-restore-window-and-refused-transitions"
GROUP = 'lifecycle'
SERVICES = ['acm-pca']


# PermanentDeletionTimeInDays is modeled 7..30; the minimum keeps the tombstone short.
_MIN_DELETION_DAYS = 7
# The modeled maximum, used only to prove a repeat delete cannot EXTEND the tombstone.
_MAX_DELETION_DAYS = 30

# A DELETED CA is still describable, and mutating it is a state error (InvalidStateException),
# not a not-found error. Re-deleting it is an idempotent no-op that keeps RestorableUntil.
_EXPECTED_DELETED_STATE_REJECTION = "InvalidStateException"
_DELETED_STATE_MESSAGE = (
    "The certificate authority is in the DELETED state and must be restored to complete "
    "this action."
)


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


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call succeeded; expected a ClientError")


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Wait out CREATING, disable if ACTIVE, then delete with the minimum window; raise on failure.

    An ACTIVE CA must be disabled first, and a delete while the CA is settling is refused.
    """
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


def _create_ca(ctx, **overrides):
    """Create a cheap short-lived-certificate root CA and register its teardown immediately.

    Retries on throttling: CreateCertificateAuthority has a low request-rate limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
    }
    body.update(overrides)
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
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


def _tag_keys(ctx, ca_arn):
    pca = ctx.client("acm-pca")
    keys = set()
    token = None
    while True:
        kwargs = {"CertificateAuthorityArn": ca_arn}
        if token:
            kwargs["NextToken"] = token
        page = pca.list_tags(**kwargs)
        for tag in page.get("Tags", []):
            keys.add(tag["Key"])
        token = page.get("NextToken")
        if not token:
            return keys


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deleted CA stays describable with a RestorableUntil, refuses tag/update and repeat-delete
    extension, and restore returns it to PENDING_CERTIFICATE with no refused mutation applied.

    Reference: https://docs.aws.amazon.com/privateca/latest/userguide/PCADeleteCA.html
    """
    pca = ctx.client("acm-pca")
    timeout_s = 180

    common_name = ctx.unique_name("sim2real-behav-pca-del-").rstrip("-")
    ca_arn = _create_ca(ctx, **{
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": common_name},
        },
    })

    # Wait for the exact status; accepting CREATING too would never observe the transition.
    live = _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )
    assert live["Status"] == "PENDING_CERTIFICATE", live["Status"]
    assert "RestorableUntil" not in live, (
        f"a live CA must not carry RestorableUntil; got {live.get('RestorableUntil')!r}"
    )

    # Pre-delete tag: proves delete+restore keeps it and the refused tag adds nothing.
    pca.tag_certificate_authority(
        CertificateAuthorityArn=ca_arn, Tags=[{"Key": "sim2real-pre", "Value": "1"}]
    )
    assert "sim2real-pre" in _tag_keys(ctx, ca_arn), "setup tag was not applied"

    before = datetime.datetime.now(datetime.timezone.utc)
    pca.delete_certificate_authority(
        CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=_MIN_DELETION_DAYS
    )

    deleted = _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "DELETED",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching DELETED",
    )
    # Soft, not hard: the ARN still resolves.
    assert deleted["Status"] == "DELETED", deleted["Status"]
    assert deleted["Arn"] == ca_arn, deleted["Arn"]
    assert deleted["CertificateAuthorityConfiguration"]["Subject"]["CommonName"] == common_name, (
        f"DescribeCertificateAuthority on the DELETED CA returned CommonName "
        f"{deleted['CertificateAuthorityConfiguration']['Subject']['CommonName']!r}, expected "
        f"{common_name!r} -- describing a deleted authority must still return the same authority"
    )

    # A day of slack for rounding; ~7 days out (not the 30-day default) shows the window held.
    restorable = deleted.get("RestorableUntil")
    assert restorable is not None, (
        "a DELETED CA must report RestorableUntil; its absence means the delete was not a "
        "restorable soft delete"
    )
    assert isinstance(restorable, datetime.datetime), (
        f"RestorableUntil must deserialize to a datetime, got {type(restorable).__name__}"
    )
    horizon_days = (restorable - before).total_seconds() / 86400.0
    assert _MIN_DELETION_DAYS - 1 <= horizon_days <= _MIN_DELETION_DAYS + 1, (
        f"RestorableUntil is {horizon_days:.2f} days out but "
        f"PermanentDeletionTimeInDays={_MIN_DELETION_DAYS} was requested; the requested "
        f"window was ignored (a 30-day value means the service defaulted)"
    )

    code_tag, msg_tag = _err(lambda: pca.tag_certificate_authority(
        CertificateAuthorityArn=ca_arn, Tags=[{"Key": "sim2real-during-delete", "Value": "1"}]
    ))
    assert code_tag == _EXPECTED_DELETED_STATE_REJECTION, (
        f"tagging a DELETED CA must be refused with "
        f"{_EXPECTED_DELETED_STATE_REJECTION}, got {code_tag!r}"
    )
    assert msg_tag == _DELETED_STATE_MESSAGE, (
        f"TagCertificateAuthority on a DELETED CA message: {msg_tag!r}"
    )
    code_upd, msg_upd = _err(lambda: pca.update_certificate_authority(
        CertificateAuthorityArn=ca_arn, Status="DISABLED"
    ))
    assert code_upd == _EXPECTED_DELETED_STATE_REJECTION, (
        f"updating the status of a DELETED CA must be refused with "
        f"{_EXPECTED_DELETED_STATE_REJECTION}, got {code_upd!r}"
    )
    assert msg_upd == (
        "The certificate authority must be in the ACTIVE or DISABLED state to be updated"
    ), (
        f"UpdateCertificateAuthority on a DELETED CA message: {msg_upd!r}"
    )
    # Re-deleting a DELETED CA is an idempotent no-op, not a refusal.
    pca.delete_certificate_authority(
        CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=_MIN_DELETION_DAYS
    )
    again = _describe(ctx, ca_arn)
    assert again["Status"] == "DELETED", (
        f"the repeat delete moved the CA out of DELETED to {again['Status']!r}"
    )
    assert again.get("RestorableUntil") == restorable, (
        f"the repeat delete restarted the tombstone: RestorableUntil moved from {restorable!r} "
        f"to {again.get('RestorableUntil')!r}"
    )
    # A longer window on re-delete must not extend the tombstone.
    pca.delete_certificate_authority(
        CertificateAuthorityArn=ca_arn, PermanentDeletionTimeInDays=_MAX_DELETION_DAYS
    )
    extended = _describe(ctx, ca_arn)
    assert extended["Status"] == "DELETED", (
        f"the second repeat delete moved the CA out of DELETED to {extended['Status']!r}"
    )
    assert extended.get("RestorableUntil") == restorable, (
        f"a repeat delete asking for {_MAX_DELETION_DAYS} days changed RestorableUntil from "
        f"{restorable!r} to {extended.get('RestorableUntil')!r}; the window of an "
        f"already-deleted CA is fixed at the first delete"
    )

    still = _describe(ctx, ca_arn)
    assert still["Status"] == "DELETED", (
        f"a refused UpdateCertificateAuthority moved the CA out of DELETED to "
        f"{still['Status']!r}"
    )
    assert still.get("RestorableUntil") == restorable, (
        f"a refused mutation changed RestorableUntil from {restorable!r} to "
        f"{still.get('RestorableUntil')!r}"
    )

    pca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
    restored = _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA returning to PENDING_CERTIFICATE after restore",
    )
    assert restored["Status"] == "PENDING_CERTIFICATE", (
        f"a restored CA must return to the status it held before deletion "
        f"(PENDING_CERTIFICATE), got {restored['Status']!r}"
    )
    assert "RestorableUntil" not in restored, (
        f"a restored CA must no longer carry RestorableUntil; got "
        f"{restored.get('RestorableUntil')!r}"
    )
    assert restored["CreatedAt"] == live["CreatedAt"], (
        f"restore must not re-create the authority: CreatedAt moved from "
        f"{live['CreatedAt']!r} to {restored['CreatedAt']!r}"
    )

    keys = _tag_keys(ctx, ca_arn)
    assert "sim2real-during-delete" not in keys, (
        "a tag refused with a state error while the CA was DELETED was applied anyway; "
        "the refusal was cosmetic"
    )
    assert "sim2real-pre" in keys, (
        f"the tag applied before deletion did not survive delete+restore; tags now: "
        f"{sorted(keys)}"
    )

    # Control: the mutation refused while DELETED now succeeds.
    pca.tag_certificate_authority(
        CertificateAuthorityArn=ca_arn, Tags=[{"Key": "sim2real-post", "Value": "1"}]
    )
    assert "sim2real-post" in _tag_keys(ctx, ca_arn), (
        "tagging the restored CA failed, so the refusals above were not specific to the "
        "DELETED state"
    )
    pca.untag_certificate_authority(
        CertificateAuthorityArn=ca_arn, Tags=[{"Key": "sim2real-post", "Value": "1"}]
    )
    assert "sim2real-post" not in _tag_keys(ctx, ca_arn), "untag did not remove the tag"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
