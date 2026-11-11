"""list-jobs-filters-by-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-jobs-filters-by-status"
GROUP = "data-plane"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListJobs' Status filter actually filters server-side: a SUBMITTED job shows up under
    Status=SUBMITTED but not Status=CANCELED, and a CANCELED job shows up the other way
    around -- a backend that ignores the filter and returns everything would fail both sides."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)
    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Status="PAUSED")
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")

    submitted_job = _create_job_with_retry(mc, Role=role_arn, Queue=queue_name, Settings=settings)["Job"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=submitted_job["Id"]))
    canceled_job = _create_job_with_retry(mc, Role=role_arn, Queue=queue_name, Settings=settings)["Job"]
    mc.cancel_job(Id=canceled_job["Id"])

    # give the CANCELED transition a moment to land before we query it
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        if mc.get_job(Id=canceled_job["Id"])["Job"]["Status"] == "CANCELED":
            break
        time.sleep(2.0)

    submitted_ids = _list_all_job_ids(mc, Status="SUBMITTED")
    assert submitted_job["Id"] in submitted_ids, (
        f"expected SUBMITTED job {submitted_job['Id']} in ListJobs(Status=SUBMITTED), "
        f"got {submitted_ids}"
    )
    assert canceled_job["Id"] not in submitted_ids, (
        f"expected CANCELED job {canceled_job['Id']} absent from ListJobs(Status=SUBMITTED), "
        f"got {submitted_ids}"
    )

    canceled_ids = _list_all_job_ids(mc, Status="CANCELED")
    assert canceled_job["Id"] in canceled_ids, (
        f"expected CANCELED job {canceled_job['Id']} in ListJobs(Status=CANCELED), "
        f"got {canceled_ids}"
    )
    assert submitted_job["Id"] not in canceled_ids, (
        f"expected SUBMITTED job {submitted_job['Id']} absent from ListJobs(Status=CANCELED), "
        f"got {canceled_ids}"
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


def _list_all_job_ids(mc, **kwargs) -> list:
    ids: list = []
    token = None
    for _ in range(25):
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        resp = mc.list_jobs(**params)
        ids.extend(j["Id"] for j in resp.get("Jobs", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
