"""signing-profile-status-transitions-to-revoked."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signing-profile-status-transitions-to-revoked"
GROUP = "state"
SERVICES = ["signer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new signing profile reads back Active, and after RevokeSigningProfile GetSigningProfile eventually
    reports status Revoked with the supplied reason as statusReason.
    """
    signer = ctx.client("signer")
    profile_name = ctx.unique_name("sim2real_signer_profstat_").replace("-", "_")

    signer.put_signing_profile(
        profileName=profile_name,
        platformId="Notation-OCI-SHA384-ECDSA",
        tags={"sim2real-env": "behavioral"},
    )
    ctx.on_cleanup(lambda: _safe_cancel(signer, profile_name))

    initial = signer.get_signing_profile(profileName=profile_name)
    assert initial["status"] == "Active", f"expected Active status on creation, got {initial['status']!r}"

    reason = "behavioral-check-revoke-reason"
    signer.revoke_signing_profile(
        profileName=profile_name,
        profileVersion=initial["profileVersion"],
        effectiveTime=datetime.now(timezone.utc) - timedelta(minutes=1),
        reason=reason,
    )

    final = _poll_until_status(signer, profile_name, "Revoked")
    assert final is not None, "signing profile never transitioned to Revoked"
    assert final["status"] == "Revoked", f"expected Revoked status, got {final['status']!r}"
    assert final["statusReason"] == reason, f"expected statusReason {reason!r}, got {final['statusReason']!r}"


def _safe_cancel(signer, profile_name: str) -> None:
    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_status(signer, profile_name: str, want_status: str, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = signer.get_signing_profile(profileName=profile_name)
        if resp["status"] == want_status:
            return resp
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
