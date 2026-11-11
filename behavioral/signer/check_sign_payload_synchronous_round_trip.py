"""sign-payload-synchronous-round-trip."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sign-payload-synchronous-round-trip"
GROUP = "data-plane"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SignPayload synchronously produces a signature and a terminal, describable job."""
    signer = ctx.client("signer")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = _profile_name(ctx, "signsync")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))

    signer.put_signing_profile(
        profileName=name,
        platformId=NOTATION_PLATFORM,
        tags={"sim2real-check": CHECK},
    )

    resp = signer.sign_payload(
        profileName=name,
        payload=_notation_payload("round-trip"),
        payloadFormat=PAYLOAD_FORMAT,
    )
    assert resp["jobId"], f"expected a non-empty jobId, got {resp.get('jobId')!r}"
    assert resp["jobOwner"] == account_id, (
        f"expected jobOwner {account_id!r} (this caller's account), got {resp['jobOwner']!r}"
    )
    assert resp["signature"], f"expected a non-empty signature, got {resp.get('signature')!r}"

    def probe():
        return signer.describe_signing_job(jobId=resp["jobId"])

    job = _poll_until(probe, lambda j: j["status"] != "InProgress", timeout_s=30.0, interval_s=2.0)
    assert job["status"] == "Succeeded", (
        f"expected terminal status 'Succeeded' for job {resp['jobId']}, got {job['status']!r}"
    )
    assert job["profileName"] == name, (
        f"expected describe_signing_job to report profileName {name!r}, got {job['profileName']!r}"
    )
    assert job["platformId"] == NOTATION_PLATFORM, (
        f"expected describe_signing_job to report platformId {NOTATION_PLATFORM!r}, got {job['platformId']!r}"
    )


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
