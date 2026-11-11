"""concurrent-job-submission-unique-ids."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-job-submission-unique-ids"
GROUP = "concurrency"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateJob calls on one queue all succeed with distinct job Ids, and ListJobs on the queue
    returns exactly those Ids, so each response is backed by its own persisted job."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)
    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Status="PAUSED", Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")

    # warm up: absorb any IAM-propagation ForbiddenException serially before racing, so the
    # concurrency assertion below is about job-id uniqueness, not role propagation timing.
    warm = _create_job_with_retry(
        mc, Role=role_arn, Queue=queue_name, Settings=settings, Tags={"sim2real-check": CHECK}
    )
    job_ids = [warm["Job"]["Id"]]

    racers = 10

    def submit(_i):
        resp = mc.create_job(
            Role=role_arn, Queue=queue_name, Settings=settings, Tags={"sim2real-check": CHECK}
        )
        return resp["Job"]["Id"]

    with ThreadPoolExecutor(max_workers=racers) as ex:
        job_ids.extend(ex.map(submit, range(racers)))

    for jid in job_ids:
        ctx.on_cleanup(lambda jid=jid: mc.cancel_job(Id=jid))

    assert len(job_ids) == racers + 1, f"expected {racers + 1} CreateJob responses, got {len(job_ids)}"
    assert len(set(job_ids)) == len(job_ids), f"duplicate job id under concurrency: {job_ids}"

    # independent read at the destination -- a ListJobs against the queue, issued through a
    # different operation than the one that mutated, not the CreateJob responses themselves.
    listed_ids = _list_all_job_ids(mc, Queue=queue_name)
    assert set(listed_ids) == set(job_ids), (
        f"ListJobs at the destination disagrees with the CreateJob responses: "
        f"listed={sorted(listed_ids)} created={sorted(job_ids)}"
    )
    assert len(listed_ids) == len(job_ids), (
        f"ListJobs returned {len(listed_ids)} jobs for a queue that received {len(job_ids)} "
        f"distinct CreateJob calls -- {job_ids}"
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
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
