"""cancel-already-canceled-job-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-already-canceled-job-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconvert"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelJob moves a SUBMITTED job to CANCELED, and a repeated CancelJob on the CANCELED job succeeds
    without error (idempotent) and leaves its Status CANCELED."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)
    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Status="PAUSED", Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")
    resp = _create_job_with_retry(mc, Role=role_arn, Queue=queue_name, Settings=settings)
    job_id = resp["Job"]["Id"]

    # positive control: canceling a SUBMITTED job succeeds
    mc.cancel_job(Id=job_id)
    deadline = time.monotonic() + 20.0
    status = None
    while time.monotonic() < deadline:
        status = mc.get_job(Id=job_id)["Job"]["Status"]
        if status == "CANCELED":
            break
        time.sleep(2.0)
    assert status == "CANCELED", f"positive control: expected CANCELED, got {status!r}"

    # Canceling an already-CANCELED job succeeds again (no ConflictException) and must not move
    # the job away from CANCELED.
    try:
        mc.cancel_job(Id=job_id)
        code = None
    except ClientError as e:
        code = e.response["Error"]["Code"]
    assert code is None, f"expected idempotent no-op re-cancel of a CANCELED job, got {code!r}"

    # effect absent: status remains CANCELED, unaffected by the repeat call
    job2 = mc.get_job(Id=job_id)["Job"]
    assert job2["Status"] == "CANCELED", f"expected CANCELED unaffected, got {job2['Status']!r}"


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


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
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real", "Value": CHECK}]
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
