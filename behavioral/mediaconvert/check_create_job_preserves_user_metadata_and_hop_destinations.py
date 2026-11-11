"""create-job-preserves-user-metadata-and-hop-destinations."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-job-preserves-user-metadata-and-hop-destinations"
GROUP = "control-plane"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateJob's compound settings -- UserMetadata, Priority, and HopDestinations -- round-trip
    through GetJob unchanged, not just the top-level Id/Status/Queue smoke fields."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)

    source_queue = ctx.unique_name("sim2real-mc-queue-src-")
    hop_queue = ctx.unique_name("sim2real-mc-queue-hop-")
    mc.create_queue(Name=source_queue, Status="PAUSED")
    ctx.on_cleanup(lambda: mc.delete_queue(Name=source_queue))
    hop_queue_arn = mc.create_queue(Name=hop_queue, Status="PAUSED")["Queue"]["Arn"]
    ctx.on_cleanup(lambda: mc.delete_queue(Name=hop_queue))

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")

    resp = _create_job_with_retry(
        mc,
        Role=role_arn,
        Queue=source_queue,
        Priority=5,
        Settings=settings,
        UserMetadata={"env": "test", "team": "sim2real"},
        HopDestinations=[{"Queue": hop_queue, "WaitMinutes": 1}],
    )
    job_id = resp["Job"]["Id"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=job_id))

    job = mc.get_job(Id=job_id)["Job"]
    assert job["Priority"] == 5, f"expected Priority=5, got {job.get('Priority')!r}"
    assert job["UserMetadata"] == {"env": "test", "team": "sim2real"}, (
        f"expected UserMetadata={{'env': 'test', 'team': 'sim2real'}}, got {job.get('UserMetadata')!r}"
    )
    hops = job["HopDestinations"]
    assert len(hops) == 1, f"expected exactly 1 HopDestination, got {len(hops)}: {hops!r}"
    assert hops[0]["Queue"] in (hop_queue, hop_queue_arn), (
        f"expected HopDestinations[0].Queue in {(hop_queue, hop_queue_arn)!r}, got {hops[0].get('Queue')!r}"
    )
    assert hops[0]["WaitMinutes"] == 1, (
        f"expected HopDestinations[0].WaitMinutes=1, got {hops[0].get('WaitMinutes')!r}"
    )


def _output_groups(output_uri: str) -> list:
    return [
        {
            "Name": "File Group",
            "OutputGroupSettings": {
                "Type": "FILE_GROUP_SETTINGS",
                "FileGroupSettings": {"Destination": output_uri},
            },
            "Outputs": [
                {
                    "ContainerSettings": {"Container": "MP4"},
                    "VideoDescription": {
                        "CodecSettings": {
                            "Codec": "H_264",
                            "H264Settings": {
                                "RateControlMode": "QVBR",
                                "QvbrSettings": {"QvbrQualityLevel": 7},
                                "MaxBitrate": 5000000,
                                "SceneChangeDetect": "ENABLED",
                            },
                        }
                    },
                }
            ],
        }
    ]


def _job_settings(input_uri: str, output_uri: str) -> dict:
    return {"Inputs": [{"FileInput": input_uri}], "OutputGroups": _output_groups(output_uri)}


def _create_mediaconvert_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mc-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "mediaconvert.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_job_with_retry(mc, *, timeout_s: float = 45.0, interval_s: float = 3.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mc.create_job(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ForbiddenException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
