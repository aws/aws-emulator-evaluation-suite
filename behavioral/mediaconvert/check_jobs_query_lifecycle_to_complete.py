"""jobs-query-lifecycle-to-complete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jobs-query-lifecycle-to-complete"
GROUP = "state"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartJobsQuery returns an Id whose GetJobsQueryResults reaches COMPLETE and lists the job this run
    submitted, so the query reads real jobs rather than answering an empty result set."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)
    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Status="PAUSED")
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    settings = _job_settings(f"s3://{bucket}/in.mp4", f"s3://{bucket}/out/")
    job = _create_job_with_retry(mc, Role=role_arn, Queue=queue_name, Settings=settings)["Job"]
    job_id = job["Id"]
    queue_arn = job["Queue"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=job_id))

    job_ids: set = set()
    query_id = None
    status = None
    query_deadline = time.monotonic() + 60.0
    while time.monotonic() < query_deadline:
        started = mc.start_jobs_query(FilterList=[{"Key": "queue", "Values": [queue_arn]}], MaxResults=5)
        query_id = started["Id"]
        assert query_id, f"expected StartJobsQuery to mint a query id, got {started!r}"

        poll_deadline = time.monotonic() + 30.0
        status = None
        jobs = None
        while time.monotonic() < poll_deadline:
            resp = mc.get_jobs_query_results(Id=query_id)
            status = resp.get("Status")
            jobs = resp.get("Jobs")
            if status in ("COMPLETE", "ERROR"):
                break
            time.sleep(2.0)
        assert status == "COMPLETE", f"expected query {query_id} to reach COMPLETE, last saw {status!r}"

        job_ids = {j["Id"] for j in jobs or []}
        if job_id in job_ids:
            break
        time.sleep(3.0)

    assert job_id in job_ids, (
        f"expected submitted job {job_id} (queue {queue_arn}) to appear in a completed jobs query "
        f"within 60s, last query {query_id} saw {job_ids!r}"
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
