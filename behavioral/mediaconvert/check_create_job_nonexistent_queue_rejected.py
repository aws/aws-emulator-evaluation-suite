"""create-job-nonexistent-queue-rejected."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "create-job-nonexistent-queue-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconvert"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateJob naming a queue that was never created fails NotFoundException with the exact
    message and creates no job, while the identical settings against a real queue this run
    created are accepted and the job runs to COMPLETE."""
    require_tools("ffmpeg")
    ffmpeg = shutil.which("ffmpeg")

    mc = ctx.client("mediaconvert")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    bucket_args = {"Bucket": bucket}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        bucket_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**bucket_args)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    source_key = "input/clip.mp4"
    clip_bytes = _make_source_clip(ffmpeg)
    s3.put_object(Bucket=bucket, Key=source_key, Body=clip_bytes, ContentType="video/mp4")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=source_key))

    role_arn = _create_mediaconvert_role(ctx, bucket)
    settings = _job_settings(bucket, source_key)

    missing_queue = ctx.unique_name("sim2real-mc-queue-missing-")
    code, message = _error(
        lambda: _create_job_retrying_role_propagation(mc, Role=role_arn, Queue=missing_queue, Settings=settings)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected = "The resource you specified in queue was not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # independent read: the rejected call minted no queue for a job to land on, so even a
    # read of it still sees no such resource
    list_code, list_message = _error(lambda: mc.list_jobs(Queue=missing_queue))
    assert list_code == "NotFoundException", f"expected NotFoundException, got {list_code!r}"
    assert list_message == expected, f"expected message {expected!r}, got {list_message!r}"

    # positive control: the same settings against a queue this run actually created are accepted
    real_queue = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=real_queue)
    ctx.on_cleanup(lambda: mc.delete_queue(Name=real_queue))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="output/clip-transcoded.mp4"))

    job = _submit_and_wait(mc, role_arn, real_queue, settings)
    job_id = job["Id"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=job_id))
    assert job["Status"] == "COMPLETE", (
        f"expected the job to reach COMPLETE, got {job['Status']!r} "
        f"(ErrorCode={job.get('ErrorCode')!r}, ErrorMessage={job.get('ErrorMessage')!r})"
    )


def _make_source_clip(ffmpeg: str) -> bytes:
    """A real, tiny 2s/320x240 H.264+AAC MP4 ffmpeg generates locally -- not an AWS call."""
    with tempfile.TemporaryDirectory() as tmp:
        clip_path = os.path.join(tmp, "clip.mp4")
        subprocess.run(
            [
                ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
                "-f", "lavfi", "-i", "testsrc=size=320x240:rate=30:duration=2",
                "-f", "lavfi", "-i", "anullsrc=r=48000:cl=mono",
                "-t", "2",
                "-pix_fmt", "yuv420p",
                "-c:v", "libx264", "-c:a", "aac", "-shortest",
                clip_path,
            ],
            check=True,
            timeout=60,
        )
        with open(clip_path, "rb") as f:
            return f.read()


def _job_settings(bucket: str, source_key: str) -> dict:
    return {
        "Inputs": [
            {
                "FileInput": f"s3://{bucket}/{source_key}",
                "AudioSelectors": {"Audio Selector 1": {"DefaultSelection": "DEFAULT"}},
            }
        ],
        "OutputGroups": [
            {
                "Name": "File Group",
                "OutputGroupSettings": {
                    "Type": "FILE_GROUP_SETTINGS",
                    "FileGroupSettings": {"Destination": f"s3://{bucket}/output/"},
                },
                "Outputs": [
                    {
                        "NameModifier": "-transcoded",
                        "ContainerSettings": {"Container": "MP4"},
                        "VideoDescription": {
                            "CodecSettings": {
                                "Codec": "H_264",
                                "H264Settings": {
                                    "RateControlMode": "QVBR",
                                    "QvbrSettings": {"QvbrQualityLevel": 7},
                                    "MaxBitrate": 5000000,
                                },
                            }
                        },
                        "AudioDescriptions": [
                            {
                                "CodecSettings": {
                                    "Codec": "AAC",
                                    "AacSettings": {
                                        "Bitrate": 96000,
                                        "CodingMode": "CODING_MODE_1_0",
                                        "SampleRate": 48000,
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def _create_mediaconvert_role(ctx, bucket: str) -> str:
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))

    policy_name = "s3-source-and-output-access"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return arn


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_job_retrying_role_propagation(mc, *, timeout_s: float = 45.0, interval_s: float = 3.0, **kwargs):
    """A just-created role's trust policy can take a few seconds to propagate before MediaConvert
    can assume it; retry ForbiddenException within a bounded window before treating it as real."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mc.create_job(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ForbiddenException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _submit_and_wait(mc, role_arn: str, queue_name: str, settings: dict, *, timeout_s: float = 90.0) -> dict:
    """CreateJob, then poll GetJob to a terminal status.

    A just-created role's trust policy can take a few seconds to propagate; MediaConvert then
    fails the job itself with ErrorCode 1434 (AssumeRole failed), or with 1401 access denied on
    the input while the role's inline S3 policy propagates, rather than rejecting CreateJob.
    Resubmitting within a bounded window is the retry that makes this correct.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        resp = _create_job_retrying_role_propagation(mc, Role=role_arn, Queue=queue_name, Settings=settings)
        job_id = resp["Job"]["Id"]
        job = resp["Job"]
        poll_deadline = time.monotonic() + 240.0
        while time.monotonic() < poll_deadline:
            if job["Status"] in ("COMPLETE", "ERROR", "CANCELED"):
                break
            time.sleep(5.0)
            job = mc.get_job(Id=job_id)["Job"]
        propagating = job.get("ErrorCode") == 1434 or (
            job.get("ErrorCode") == 1401 and "Access denied" in job.get("ErrorMessage", "")
        )
        if job["Status"] == "ERROR" and propagating and time.monotonic() < deadline:
            time.sleep(5.0)
            continue
        return job


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
