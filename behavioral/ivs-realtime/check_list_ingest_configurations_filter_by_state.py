"""list-ingest-configurations-filter-by-state."""
from __future__ import annotations

import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "list-ingest-configurations-filter-by-state"
GROUP = "state"
SERVICES = ["ivs-realtime"]


def _poll_until(probe, predicate, timeout_s=45.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for predicate; last observed {last!r}")


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


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListIngestConfigurations filterByState follows the actual state: a configuration driven ACTIVE by a live
    RTMP publish lists only under ACTIVE, and its INACTIVE sibling only under INACTIVE."""
    require_tools("ffmpeg")

    ivs = ctx.client("ivs-realtime")
    stage = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"))["stage"]
    stage_arn = stage["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))

    active_cfg = ivs.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest-active-"),
        stageArn=stage_arn,
        ingestProtocol="RTMP",
        insecureIngest=True,
    )["ingestConfiguration"]
    active_arn = active_cfg["arn"]
    ctx.on_cleanup(lambda: ivs.delete_ingest_configuration(arn=active_arn, force=True))

    inactive_cfg = ivs.create_ingest_configuration(
        name=ctx.unique_name("sim2real-ingest-inactive-"),
        stageArn=stage_arn,
        ingestProtocol="RTMPS",
    )["ingestConfiguration"]
    inactive_arn = inactive_cfg["arn"]
    ctx.on_cleanup(lambda: ivs.delete_ingest_configuration(arn=inactive_arn))

    endpoint = ctx.endpoint_url(stage["endpoints"]["rtmp"]).rstrip("/")
    stream_key = active_cfg["streamKey"]
    candidate_urls = [f"{endpoint}/app/{stream_key}", f"{endpoint}/{stream_key}"]

    proc = None
    live_cfg = None
    try:
        for url in candidate_urls:
            proc = _ffmpeg_publish(url, duration_s=60)
            live_cfg = _poll_until(
                lambda: ivs.get_ingest_configuration(arn=active_arn)["ingestConfiguration"],
                lambda c: c["state"] == "ACTIVE",
                timeout_s=20.0,
            )
            if live_cfg and live_cfg["state"] == "ACTIVE":
                break
            proc.kill()
            proc.wait(timeout=10)
            proc = None

        assert live_cfg is not None and live_cfg["state"] == "ACTIVE", (
            f"expected active_cfg to reach ACTIVE via a live RTMP publish, got {live_cfg!r}"
        )

        active_arns = {
            c["arn"]
            for c in ivs.list_ingest_configurations(filterByState="ACTIVE")["ingestConfigurations"]
        }
        inactive_arns = {
            c["arn"]
            for c in ivs.list_ingest_configurations(filterByState="INACTIVE")["ingestConfigurations"]
        }

        assert active_arn in active_arns, (
            f"expected the currently-publishing config {active_arn} in filterByState=ACTIVE, "
            f"got {active_arns}"
        )
        assert active_arn not in inactive_arns, (
            f"expected the currently-publishing config {active_arn} absent from "
            f"filterByState=INACTIVE, got {inactive_arns}"
        )
        assert inactive_arn in inactive_arns, (
            f"expected the never-published config {inactive_arn} in filterByState=INACTIVE, "
            f"got {inactive_arns}"
        )
        assert inactive_arn not in active_arns, (
            f"expected the never-published config {inactive_arn} absent from "
            f"filterByState=ACTIVE, got {active_arns}"
        )
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
