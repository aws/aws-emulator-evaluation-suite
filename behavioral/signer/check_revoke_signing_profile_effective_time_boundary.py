"""revoke-signing-profile-effective-time-boundary."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-signing-profile-effective-time-boundary"
GROUP = "state"
SERVICES = ["signer"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RevokeSigningProfile on a missing profile fails with ResourceNotFoundException and the exact message;
    with an effectiveTime an hour ago, GetRevocationStatus reports the version revoked for a later
    signatureTimestamp and not for an earlier one.
    """
    signer = ctx.client("signer")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Negative sub-test (documented, exact code): revoking a profile that was never
    # created is rejected, proving the service does not silently no-op.
    missing_name = ctx.unique_name("sim2real_signer_nope_").replace("-", "_")
    code, message = _client_error(
        lambda: signer.revoke_signing_profile(
            profileName=missing_name,
            profileVersion="AAAAAAAAAA",
            effectiveTime=datetime.now(timezone.utc),
            reason="probe-nonexistent-profile",
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Signing Profile with name {missing_name} and version AAAAAAAAAA does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    profile_name = ctx.unique_name("sim2real_signer_profeff_").replace("-", "_")
    put_resp = signer.put_signing_profile(
        profileName=profile_name,
        platformId="Notation-OCI-SHA384-ECDSA",
        tags={"sim2real-check": CHECK},
    )
    profile_version = put_resp["profileVersion"]
    profile_version_arn = put_resp["profileVersionArn"]
    ctx.on_cleanup(lambda: _safe_cancel(signer, profile_name))

    now = datetime.now(timezone.utc)
    effective_time = now - timedelta(hours=1)
    before_effective_ts = now - timedelta(hours=2)
    after_effective_ts = now

    signer.revoke_signing_profile(
        profileName=profile_name,
        profileVersion=profile_version,
        effectiveTime=effective_time,
        reason="behavioral-check-effective-time-boundary",
    )

    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:{account_id}:/signing-jobs/{'k' * 20}",
        profileVersionArn=profile_version_arn,
        certificateHashes=["a" * 192],
    )

    # Before the effective time: never revoked. An immediate read could pass only because
    # revocation has not propagated yet, so it is read again below once the after-side poll
    # has proven propagation completed.
    before_resp = signer.get_revocation_status(signatureTimestamp=before_effective_ts, **common)
    assert profile_version_arn not in before_resp["revokedEntities"], (
        f"expected {profile_version_arn} absent from revokedEntities for a signatureTimestamp "
        f"before effectiveTime, got {before_resp['revokedEntities']!r}"
    )

    # After the effective time: eventually revoked (bounded poll for propagation).
    after_revoked = _poll_until_revoked(signer, profile_version_arn, after_effective_ts, common)
    assert after_revoked, (
        f"expected {profile_version_arn} to appear revoked for a signatureTimestamp after "
        f"effectiveTime within the poll window, it never did"
    )

    # Now that the after-side poll has proven revocation has fully propagated, the
    # before-side outcome must still hold -- this is the boundary condition itself,
    # not an artifact of revocation not having synced yet.
    final_before_resp = signer.get_revocation_status(signatureTimestamp=before_effective_ts, **common)
    assert profile_version_arn not in final_before_resp["revokedEntities"], (
        f"expected {profile_version_arn} to remain absent from revokedEntities for a "
        f"signatureTimestamp before effectiveTime even after revocation fully propagated, "
        f"got {final_before_resp['revokedEntities']!r}"
    )


def _client_error(fn):
    """Call fn(); return its ClientError code and message; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _safe_cancel(signer, profile_name: str) -> None:
    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_revoked(signer, profile_version_arn, ts, common, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = signer.get_revocation_status(signatureTimestamp=ts, **common)
        if profile_version_arn in resp["revokedEntities"]:
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
