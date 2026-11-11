"""job-progresses-to-error-on-missing-input."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-progresses-to-error-on-missing-input"
GROUP = "data-plane"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A job on an ACTIVE queue whose S3 input bucket does not exist goes from SUBMITTED to ERROR (not
    stuck, not COMPLETE) with ErrorCode 1404 and an ErrorMessage naming the missing bucket: the engine
    actually opens the submitted input."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)
    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Tags={"sim2real-audit": "job-progresses-to-error"})
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))

    bucket = ctx.unique_name("sim2real-mc-nonexistent-")
    input_uri = f"s3://{bucket}/does-not-exist.mp4"
    settings = _job_settings(input_uri, f"s3://{bucket}/out/")
    resp = _create_job_with_retry(
        mc,
        Role=role_arn,
        Queue=queue_name,
        Settings=settings,
        Tags={"sim2real-audit": "job-progresses-to-error"},
    )
    job_id = resp["Job"]["Id"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=job_id))

    deadline = time.monotonic() + 240.0
    status = resp["Job"]["Status"]
    while time.monotonic() < deadline:
        job = mc.get_job(Id=job_id)["Job"]
        status = job["Status"]
        if status in ("ERROR", "COMPLETE", "CANCELED"):
            break
        time.sleep(3.0)

    assert status == "ERROR", f"expected a real backend to fail an unreadable input, got {status}"
    job = mc.get_job(Id=job_id)["Job"]
    # MediaConvert answers an unopenable input with ErrorCode 1404 and names the input in
    # ErrorMessage; pinning both fails a target that returns one canned error for every job.
    error_code = job.get("ErrorCode")
    assert error_code == 1404, f"expected MediaConvert's input-probe-failure code 1404, got {error_code!r}"
    error_message = job.get("ErrorMessage") or ""
    assert bucket in error_message, (
        f"expected ErrorMessage to name the unreadable input {input_uri!r} this run actually "
        f"submitted, got {error_message!r}"
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
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-audit", "Value": "job-progresses-to-error"}],
    )["Role"]["Arn"]
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
