"""delete-queue-with-active-job-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-queue-with-active-job-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconvert"]
NOT_FOUND_MESSAGE = "The resource you specified in name was not found."
IN_USE_MESSAGE = (
    "The queue is currently in use and cannot be deleted. To resolve: Stop submitting any other "
    "requests to modify this queue, and cancel any remaining jobs that are in a SUBMITTED or "
    "PROGRESSING state in this queue. Then, resubmit your request."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQueue on a queue with a SUBMITTED job fails ConflictException with the exact in-use message
    and leaves queue and job intact; after the job is canceled the same delete succeeds and GetQueue
    fails NotFoundException, as it does for an empty queue deleted directly."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)
    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Status="PAUSED")
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")
    resp = _create_job_with_retry(mc, Role=role_arn, Queue=queue_name, Settings=settings)
    job_id = resp["Job"]["Id"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=job_id))

    code, message = _error(lambda: mc.delete_queue(Name=queue_name))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert message == IN_USE_MESSAGE, f"expected message {IN_USE_MESSAGE!r}, got {message!r}"

    # effect absent: the queue and the job are both still there
    got = mc.get_queue(Name=queue_name)["Queue"]
    assert got["Name"] == queue_name, f"queue should survive the rejected delete, got {got!r}"
    job = mc.get_job(Id=job_id)["Job"]
    assert job["Status"] == "SUBMITTED", f"job should be untouched by the rejected delete, got {job['Status']!r}"

    # restore: canceling the job clears the conflict and the identical delete succeeds
    mc.cancel_job(Id=job_id)
    deadline = time.monotonic() + 30.0
    status = None
    while time.monotonic() < deadline:
        status = mc.get_job(Id=job_id)["Job"]["Status"]
        if status == "CANCELED":
            break
        time.sleep(2.0)
    assert status == "CANCELED", f"expected job to cancel, got {status!r}"

    deadline = time.monotonic() + 30.0
    while True:
        try:
            mc.delete_queue(Name=queue_name)
            break
        except ClientError as e:
            restore_code = e.response["Error"]["Code"]
            if restore_code != "ConflictException" or time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected delete to succeed once the job is canceled, got {restore_code!r}"
                ) from e
            time.sleep(2.0)
    code3, message3 = _error(lambda: mc.get_queue(Name=queue_name))
    assert code3 == "NotFoundException", f"expected queue gone after the restored delete, got {code3!r}"
    assert message3 == NOT_FOUND_MESSAGE, f"expected message {NOT_FOUND_MESSAGE!r}, got {message3!r}"

    # positive control: an empty queue deletes cleanly
    control_name = ctx.unique_name("sim2real-mc-queue-empty-")
    mc.create_queue(Name=control_name)
    mc.delete_queue(Name=control_name)
    code2, message2 = _error(lambda: mc.get_queue(Name=control_name))
    assert code2 == "NotFoundException", f"expected empty queue gone after delete, got {code2!r}"
    assert message2 == NOT_FOUND_MESSAGE, f"expected message {NOT_FOUND_MESSAGE!r}, got {message2!r}"


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
