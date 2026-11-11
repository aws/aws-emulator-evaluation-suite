"""sign-payload-missing-iam-permission-denied."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sign-payload-missing-iam-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["signer"]

NOTATION_PLATFORM = "Notation-OCI-SHA384-ECDSA"
PAYLOAD_FORMAT = "application/vnd.cncf.notary.payload.v1+json"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM principal with zero attached permissions is denied SignPayload by IAM enforcement,
    no job is ever created for the denied attempt, and the same call from a permissioned identity
    both succeeds and reaches a real, independently-readable Succeeded job."""
    signer = ctx.client("signer")
    iam = ctx.client("iam")
    account_id = ctx.account

    profile_name = _profile_name(ctx, "iamdeny")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, profile_name))
    signer.put_signing_profile(
        profileName=profile_name,
        platformId=NOTATION_PLATFORM,
        tags={"sim2real-env": "behavioral"},
    )

    user_name = ctx.unique_name("sim2real-signer-nouser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_quietly(iam, user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    )

    low_priv = ctx.client(
        "signer",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    def probe():
        return _error(
            lambda: low_priv.sign_payload(
                profileName=profile_name,
                payload=_notation_payload("no-permission"),
                payloadFormat=PAYLOAD_FORMAT,
            )
        )

    code, message = _poll_until(
        probe, lambda err: err[0] == "AccessDeniedException", timeout_s=45.0, interval_s=3.0
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException from a zero-permission caller, got {code!r}"
    )
    profile_arn = f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/{profile_name}"
    expected = (
        f"User: arn:aws:iam::{account_id}:user/{user_name} is not authorized to perform: "
        f"signer:SignPayload on resource: {profile_arn} because no identity-based policy allows "
        "the signer:SignPayload action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the denied attempt never produced a job for this profile.
    denied_jobs = _succeeded_jobs_for_profile(signer, profile_name, account_id)
    assert denied_jobs == [], (
        f"a denied SignPayload call must not create a job, but found succeeded jobs "
        f"{denied_jobs!r} for profile {profile_name!r}"
    )

    # Positive control: the fully-permissioned test identity can still sign successfully,
    # and the job is independently readable (and describable) at the destination -- not just
    # echoed back in the mutating call's own response.
    control_resp = signer.sign_payload(
        profileName=profile_name,
        payload=_notation_payload("has-permission"),
        payloadFormat=PAYLOAD_FORMAT,
    )
    assert control_resp["jobId"], "positive-control SignPayload did not return a jobId"

    def describe_probe():
        return signer.describe_signing_job(jobId=control_resp["jobId"])

    job = _poll_until(
        describe_probe, lambda j: j["status"] != "InProgress", timeout_s=30.0, interval_s=2.0
    )
    assert job["status"] == "Succeeded", (
        f"positive-control job {control_resp['jobId']} expected Succeeded, got {job['status']!r}"
    )
    assert job["profileName"] == profile_name, (
        f"positive-control job {control_resp['jobId']} expected profileName {profile_name!r}, "
        f"got {job['profileName']!r}"
    )

    def list_probe():
        return _succeeded_jobs_for_profile(signer, profile_name, account_id)

    control_jobs = _poll_until(
        list_probe,
        lambda jobs: control_resp["jobId"] in {j["jobId"] for j in jobs},
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert control_resp["jobId"] in {j["jobId"] for j in control_jobs}, (
        f"job {control_resp['jobId']} did not appear via ListSigningJobs(status=Succeeded, "
        f"jobInvoker={account_id!r}) for profile {profile_name!r}"
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


def _delete_user_quietly(iam, user_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
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


def _succeeded_jobs_for_profile(signer, profile_name: str, account_id: str) -> list:
    matches = []
    next_token = None
    for _ in range(20):
        kwargs = {"status": "Succeeded", "jobInvoker": account_id, "maxResults": 25}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = signer.list_signing_jobs(**kwargs)
        matches.extend(j for j in resp.get("jobs", []) if j["profileName"] == profile_name)
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return matches


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
