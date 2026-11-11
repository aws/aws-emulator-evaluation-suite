"""sign-payload-on-canceled-profile-rejected."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sign-payload-on-canceled-profile-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SignPayload rejects requests against a Canceled profile; Active profiles still sign."""
    signer = ctx.client("signer")

    canceled_name = _profile_name(ctx, "canceled")
    signer.put_signing_profile(
        profileName=canceled_name, platformId=NOTATION_PLATFORM, tags={"sim2real-env": "behavioral"}
    )
    signer.cancel_signing_profile(profileName=canceled_name)

    def probe():
        return signer.get_signing_profile(profileName=canceled_name)["status"]

    _poll_until(probe, lambda s: s == "Canceled", timeout_s=30.0, interval_s=2.0)

    code, message = _error(
        lambda: signer.sign_payload(
            profileName=canceled_name,
            payload=_notation_payload("canceled-profile"),
            payloadFormat=PAYLOAD_FORMAT,
        )
    )
    assert code == "ValidationException", f"unexpected code: {code!r}"
    expected = f"Signing profile with name: {canceled_name} is in state Canceled"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the profile is still Canceled, not silently reactivated.
    post_status = signer.get_signing_profile(profileName=canceled_name)["status"]
    assert post_status == "Canceled", f"expected status Canceled, got {post_status!r}"

    # Positive control: a fresh Active profile signs successfully.
    active_name = _profile_name(ctx, "active")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, active_name))
    signer.put_signing_profile(
        profileName=active_name, platformId=NOTATION_PLATFORM, tags={"sim2real-env": "behavioral"}
    )
    control_resp = signer.sign_payload(
        profileName=active_name,
        payload=_notation_payload("active-profile"),
        payloadFormat=PAYLOAD_FORMAT,
    )
    assert control_resp["jobId"], f"expected control sign to return a jobId, got {control_resp.get('jobId')!r}"


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
