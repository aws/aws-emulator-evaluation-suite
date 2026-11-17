"""delete-active-ingest-configuration-without-force-rejected."""
from __future__ import annotations

import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "delete-active-ingest-configuration-without-force-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



def _poll_until(probe, predicate, timeout_s=45.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _ffmpeg_publish(url: str, duration_s: int):
    cmd = [
        "ffmpeg", "-loglevel", "error", "-re",
        "-f", "lavfi", "-i", "testsrc=size=640x360:rate=30",
        "-f", "lavfi", "-i", "sine=frequency=1000",
        "-pix_fmt", "yuv420p", "-profile:v", "baseline", "-level", "3.0",
        "-r", "30", "-g", "60",
        "-c:v", "libx264", "-b:v", "800k", "-c:a", "aac",
        "-t", str(duration_s), "-f", "flv", url,
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@tags("axis:rejection", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteIngestConfiguration on a currently-ACTIVE (publishing) ingest configuration is
    rejected with ConflictException unless force=True is passed."""
    require_tools("ffmpeg")

    ivs = ctx.client("ivs-realtime")
    stage = ivs.create_stage(
        name=ctx.unique_name("sim2real-stage-"), tags={"team": "sim2real"}
    )["stage"]
    stage_arn = stage["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))

    ingest = ivs.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest-"),
        stageArn=stage_arn,
        ingestProtocol="RTMP",
        insecureIngest=True,
        tags={"team": "sim2real"},
    )["ingestConfiguration"]
    ingest_arn = ingest["arn"]
    ingest_deleted = False
    ctx.on_cleanup(lambda: None if ingest_deleted else ivs.delete_ingest_configuration(arn=ingest_arn, force=True))

    endpoint = ctx.endpoint_url(stage["endpoints"]["rtmp"]).rstrip("/")
    stream_key = ingest["streamKey"]
    candidate_urls = [f"{endpoint}/app/{stream_key}", f"{endpoint}/{stream_key}"]

    proc = None
    active_ingest = None
    try:
        for url in candidate_urls:
            proc = _ffmpeg_publish(url, duration_s=60)
            active_ingest = _poll_until(
                lambda: ivs.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"],
                lambda c: c["state"] == "ACTIVE",
                timeout_s=20.0,
            )
            if active_ingest and active_ingest["state"] == "ACTIVE":
                break
            proc.kill()
            proc.wait(timeout=10)
            proc = None

        assert active_ingest is not None and active_ingest["state"] == "ACTIVE", active_ingest

        # Deleting a live ingest configuration without force must be rejected.
        error = _client_error(lambda: ivs.delete_ingest_configuration(arn=ingest_arn))
        assert error.get("Code") == "ConflictException", (
            f"deleting an ACTIVE ingest configuration without force was rejected with "
            f"{error!r}, expected 'ConflictException'"
        )
        assert error.get("Message") == (
            f"Unable to mutate resource {ingest_arn} while participant is actively publishing"
        ), error

        # Effect absent: it's still there and still ACTIVE.
        still_active = ivs.get_ingest_configuration(arn=ingest_arn)["ingestConfiguration"]
        assert still_active["state"] == "ACTIVE", still_active["state"]

        # Positive control: force=True deletes it even while active (and disconnects the publisher).
        ivs.delete_ingest_configuration(arn=ingest_arn, force=True)
        ingest_deleted = True
        error_after = _client_error(lambda: ivs.get_ingest_configuration(arn=ingest_arn))
        assert error_after.get("Code") == "ResourceNotFoundException", (
            f"GetIngestConfiguration after a force delete returned {error_after!r}, "
            f"expected 'ResourceNotFoundException'"
        )
        assert error_after.get("Message") == f"Resource: {ingest_arn} not found", error_after
    finally:
        if proc is not None:
            proc.kill()
            try:
                proc.wait(timeout=10)
            except Exception:
                pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
