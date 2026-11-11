"""create-job-unassumable-role-forbidden."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-job-unassumable-role-forbidden"
GROUP = "overly-permissive"
SERVICES = ["mediaconvert"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateJob with a Role that does not trust mediaconvert.amazonaws.com fails ForbiddenException with
    the exact message and leaves no job behind, rather than accepting it to fail later, while a role that
    trusts MediaConvert is accepted and the job is SUBMITTED."""
    mc = ctx.client("mediaconvert")
    iam = ctx.client("iam")

    bad_name = ctx.unique_name("sim2real-mc-badrole-")
    bad_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    bad_arn = iam.create_role(RoleName=bad_name, AssumeRolePolicyDocument=bad_trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_name))

    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Status="PAUSED")
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))
    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")

    code, message = _error(lambda: mc.create_job(Role=bad_arn, Queue=queue_name, Settings=settings))
    assert code == "ForbiddenException", f"expected ForbiddenException, got {code!r}"
    expected = (
        f"The service does not have permission to assume the IAM role: '{bad_arn}'. Please verify "
        "the role exists and has granted MediaConvert the sts:AssumeRole permission, then resubmit "
        "your job. For more information about IAM role setup, see: "
        "https://docs.aws.amazon.com/mediaconvert/latest/ug/iam-role.html"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # independent read: the rejected call must not have silently created a job on the queue
    leaked = mc.list_jobs(Queue=queue_name)["Jobs"]
    assert leaked == [], f"rejected CreateJob left {len(leaked)} job(s) on {queue_name!r}: {leaked!r}"

    # positive control: a role trusted by mediaconvert.amazonaws.com is accepted
    good_arn = _create_mediaconvert_role(ctx)
    resp = _create_job_with_retry(mc, Role=good_arn, Queue=queue_name, Settings=settings)
    job_id = resp["Job"]["Id"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=job_id))

    # independent read at the destination, not the mutating call's own response
    job = mc.get_job(Id=job_id)["Job"]
    assert job["Status"] == "SUBMITTED", f"got Status={job.get('Status')!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    # cleanups run last-registered first: the policy is detached before the role is deleted
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
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
