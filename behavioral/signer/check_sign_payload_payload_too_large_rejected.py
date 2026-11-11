"""sign-payload-payload-too-large-rejected."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sign-payload-payload-too-large-rejected"
GROUP = "overly-permissive"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SignPayload rejects a payload over the 4096-byte limit; smaller payloads still succeed."""
    signer = ctx.client("signer")
    name = _profile_name(ctx, "toolarge")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    signer.put_signing_profile(
        profileName=name, platformId=NOTATION_PLATFORM, tags={"sim2real-env": "behavioral"}
    )

    oversized_payload = b"x" * 4097
    code, message = _error(
        lambda: signer.sign_payload(
            profileName=name, payload=oversized_payload, payloadFormat=PAYLOAD_FORMAT
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Payload does not meet size requirements: [1B - 4096B]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no signing jobs exist for this brand-new profile.
    jobs = signer.list_signing_jobs(maxResults=25).get("jobs", [])
    assert not any(job.get("profileName") == name for job in jobs), (
        f"expected no signing jobs for {name!r}, found one in {jobs!r}"
    )

    # Positive control: a small, valid payload signs successfully on the same profile,
    # proven at an independent read rather than the mutating call's own response.
    control_resp = signer.sign_payload(
        profileName=name,
        payload=_notation_payload("under-limit"),
        payloadFormat=PAYLOAD_FORMAT,
    )
    assert control_resp["jobId"], "expected a jobId from the under-limit control sign"

    def probe():
        return signer.describe_signing_job(jobId=control_resp["jobId"])

    job = _poll_until(probe, lambda j: j["status"] != "InProgress", timeout_s=30.0, interval_s=2.0)
    assert job["status"] == "Succeeded", f"expected Succeeded, got {job['status']!r}"
    assert job["profileName"] == name, f"expected profileName {name!r}, got {job['profileName']!r}"


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
