"""concurrent-reads-consistent."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-reads-consistent"
GROUP = "concurrency"
SERVICES = ["signer"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """8 concurrent GetRevocationStatus calls, half for a revoked profileVersionArn and half for a never-revoked
    one, each see only their own query's answer: the revoked group always reports the revocation and the
    control group never does.
    """
    signer = ctx.client("signer")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    profile_name = ctx.unique_name("sim2real_signer_concurrent_").replace("-", "_")
    put_resp = signer.put_signing_profile(profileName=profile_name, platformId="Notation-OCI-SHA384-ECDSA")
    profile_version = put_resp["profileVersion"]
    revoked_profile_arn = put_resp["profileVersionArn"]
    ctx.on_cleanup(lambda: _safe_cancel(signer, profile_name))

    effective_time = datetime.now(timezone.utc) - timedelta(hours=1)
    signer.revoke_signing_profile(
        profileName=profile_name,
        profileVersion=profile_version,
        effectiveTime=effective_time,
        reason="behavioral-check-concurrent-reads-consistent",
    )

    probe_common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=f"arn:aws:signer:{ctx.region}:{account_id}:/signing-jobs/{'f' * 20}",
        certificateHashes=["f" * 192],
        signatureTimestamp=datetime.now(timezone.utc),
    )
    assert _poll_until_revoked(signer, revoked_profile_arn, probe_common), (
        "revoked profileVersionArn never appeared in revokedEntities before the "
        "concurrent phase started"
    )

    thread_count = 8

    def call(i: int):
        hot = i % 2 == 0
        my_hash = f"{i:x}" * 192
        # profileVersionArn and jobArn must share the same account id (real AWS
        # rejects a mismatch with ValidationException) -- the hot group's jobArn
        # therefore carries the real account, the control group's stays fabricated.
        job_account = account_id if hot else "111122223333"
        my_job_arn = f"arn:aws:signer:{ctx.region}:{job_account}:/signing-jobs/" + (f"{i:x}" * 20)
        profile_arn = (
            revoked_profile_arn
            if hot
            else f"arn:aws:signer:{ctx.region}:111122223333:/signing-profiles/n/" + (f"{i:x}" * 10)
        )
        resp = signer.get_revocation_status(
            platformId="Notation-OCI-SHA384-ECDSA",
            jobArn=my_job_arn,
            profileVersionArn=profile_arn,
            certificateHashes=[my_hash],
            signatureTimestamp=datetime.now(timezone.utc),
        )
        return i, hot, profile_arn, resp["revokedEntities"]

    with ThreadPoolExecutor(max_workers=thread_count) as pool:
        results = list(pool.map(call, range(thread_count)))

    assert len(results) == thread_count, f"expected {thread_count} results, got {len(results)}"
    for i, hot, profile_arn, revoked in results:
        if hot:
            assert revoked_profile_arn in revoked, (
                f"thread {i} (hot) queried the real revoked profile but revokedEntities "
                f"did not contain it: {revoked}"
            )
        else:
            assert revoked == [], (
                f"thread {i} (control) queried a fabricated, never-revoked profile but "
                f"got a non-empty revokedEntities: {revoked} -- likely cross-talk with a "
                f"hot thread's response"
            )
            assert revoked_profile_arn not in revoked, (
                f"thread {i} (control) leaked the real revoked profileVersionArn from "
                f"another thread's response"
            )


def _safe_cancel(signer, profile_name: str) -> None:
    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until_revoked(signer, profile_version_arn, common, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = signer.get_revocation_status(profileVersionArn=profile_version_arn, **common)
        if profile_version_arn in resp["revokedEntities"]:
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
