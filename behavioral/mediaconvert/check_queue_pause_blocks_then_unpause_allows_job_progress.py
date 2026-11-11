"""queue-pause-blocks-then-unpause-allows-job-progress."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-pause-blocks-then-unpause-allows-job-progress"
GROUP = "state"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A job on a PAUSED queue stays SUBMITTED for as long as an identical job on an ACTIVE queue takes to
    leave SUBMITTED, and leaves SUBMITTED once its queue is set ACTIVE again."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)

    paused_queue = ctx.unique_name("sim2real-mc-queue-paused-")
    mc.create_queue(Name=paused_queue, Status="PAUSED")
    ctx.on_cleanup(lambda: mc.delete_queue(Name=paused_queue))

    control_queue = ctx.unique_name("sim2real-mc-queue-active-")
    mc.create_queue(Name=control_queue)  # ACTIVE by default
    ctx.on_cleanup(lambda: mc.delete_queue(Name=control_queue))

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")

    paused_resp = _create_job_with_retry(mc, Role=role_arn, Queue=paused_queue, Settings=settings)
    paused_job_id = paused_resp["Job"]["Id"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=paused_job_id))
    assert paused_resp["Job"]["Status"] == "SUBMITTED"

    control_resp = _create_job_with_retry(mc, Role=role_arn, Queue=control_queue, Settings=settings)
    control_job_id = control_resp["Job"]["Id"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=control_job_id))
    assert control_resp["Job"]["Status"] == "SUBMITTED"

    # Twin control: keep sampling the paused job while waiting for the control job (same
    # settings, same role, ACTIVE queue) to leave SUBMITTED on its own. Every sample the
    # control is still SUBMITTED also re-asserts the paused job hasn't moved -- so the paused
    # job is held for exactly as long as real processing took to actually start the control,
    # not for an arbitrary constant.
    deadline = time.monotonic() + 180.0
    control_status = "SUBMITTED"
    while time.monotonic() < deadline:
        paused_status = mc.get_job(Id=paused_job_id)["Job"]["Status"]
        assert paused_status == "SUBMITTED", f"job left SUBMITTED while its queue was PAUSED: {paused_status}"
        control_status = mc.get_job(Id=control_job_id)["Job"]["Status"]
        if control_status != "SUBMITTED":
            break
        time.sleep(3.0)
    assert control_status != "SUBMITTED", (
        "control job on an ACTIVE queue never left SUBMITTED -- can't calibrate the block window"
    )

    mc.update_queue(Name=paused_queue, Status="ACTIVE")

    deadline = time.monotonic() + 180.0
    final_status = "SUBMITTED"
    while time.monotonic() < deadline:
        final_status = mc.get_job(Id=paused_job_id)["Job"]["Status"]
        if final_status != "SUBMITTED":
            break
        time.sleep(3.0)
    assert final_status != "SUBMITTED", "job never left SUBMITTED after its queue was unpaused"


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
                    "AudioDescriptions": [
                        {
                            "CodecSettings": {
                                "Codec": "AAC",
                                "AacSettings": {
                                    "Bitrate": 96000,
                                    "CodingMode": "CODING_MODE_2_0",
                                    "SampleRate": 48000,
                                },
                            }
                        }
                    ],
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
    # A just-created IAM role's trust policy can take a few seconds to propagate before
    # MediaConvert can assume it; retry ForbiddenException within a bounded window before
    # treating it as a real rejection.
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
