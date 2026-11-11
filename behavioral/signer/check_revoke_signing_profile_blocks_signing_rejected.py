"""revoke-signing-profile-blocks-signing-rejected."""
from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "revoke-signing-profile-blocks-signing-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RevokeSigningProfile is irreversible and permanently blocks further SignPayload calls."""
    signer = ctx.client("signer")

    revoked_name = _profile_name(ctx, "revokeprof")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, revoked_name))
    put_resp = signer.put_signing_profile(
        profileName=revoked_name, platformId=NOTATION_PLATFORM, tags=_mgmt_tags()
    )

    signer.revoke_signing_profile(
        profileName=revoked_name,
        profileVersion=put_resp["profileVersion"],
        reason="sim2real-behavioral-fidelity-check",
        effectiveTime=datetime.now(timezone.utc),
    )

    def probe():
        return signer.get_signing_profile(profileName=revoked_name)["status"]

    status = _poll_until(probe, lambda s: s == "Revoked", timeout_s=30.0, interval_s=2.0)
    assert status == "Revoked", f"profile did not settle into Revoked: last saw {status!r}"

    code, message = _error(
        lambda: signer.sign_payload(
            profileName=revoked_name,
            payload=_notation_payload("revoked-profile"),
            payloadFormat=PAYLOAD_FORMAT,
        )
    )
    assert code == "ValidationException", f"unexpected code: {code!r}"
    expected = f"Signing profile with name: {revoked_name} is in state Revoked"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the revoked profile stays Revoked, no signing job was created for it.
    after_status = signer.get_signing_profile(profileName=revoked_name)["status"]
    assert after_status == "Revoked", (
        f"profile status changed to {after_status!r} after the refused SignPayload call"
    )

    # Positive control: a fresh Active profile still signs successfully.
    control_name = _profile_name(ctx, "controlprof")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, control_name))
    signer.put_signing_profile(
        profileName=control_name, platformId=NOTATION_PLATFORM, tags=_mgmt_tags()
    )
    control_resp = signer.sign_payload(
        profileName=control_name,
        payload=_notation_payload("control-profile"),
        payloadFormat=PAYLOAD_FORMAT,
    )
    assert control_resp["jobId"], "the control profile's SignPayload call did not return a jobId"

    def control_probe():
        return signer.describe_signing_job(jobId=control_resp["jobId"])

    control_job = _poll_until(
        control_probe, lambda j: j["status"] != "InProgress", timeout_s=30.0, interval_s=2.0
    )
    assert control_job["status"] == "Succeeded", (
        f"the control profile's signing job did not succeed: {control_job['status']!r} "
        f"{control_job.get('statusReason')!r}"
    )


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-signer"}


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _cancel_quietly(signer, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _notation_payload(salt: str) -> bytes:
    digest = hashlib.sha256(f"sim2real-signer-payload-{salt}".encode("utf-8")).hexdigest()
    body = {
        "targetArtifact": {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": f"sha256:{digest}",
            "size": 1024,
            "annotations": {"sim2real.check": "true"},
        }
    }
    return json.dumps(body).encode("utf-8")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses reads as an acceptance, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
