"""create-job-from-template-inherits-output-settings."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-job-from-template-inherits-output-settings"
GROUP = "state"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateJob with a JobTemplate reference and ONLY Inputs in Settings must merge in the
    template's OutputGroups -- a backend that just stores the raw request Settings unchanged
    (ignoring the template) would return an empty/mismatched OutputGroups on the created Job."""
    mc = ctx.client("mediaconvert")
    role_arn = _create_mediaconvert_role(ctx)

    queue_name = ctx.unique_name("sim2real-mc-queue-")
    mc.create_queue(Name=queue_name, Status="PAUSED", Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mc.delete_queue(Name=queue_name))

    bucket = ctx.unique_name("sim2real-mc-bucket-")
    input_uri = f"s3://{bucket}/input.mp4"
    output_uri = f"s3://{bucket}/out/"

    template_name = ctx.unique_name("sim2real-mc-tmpl-")
    template_arn = mc.create_job_template(
        Name=template_name,
        Settings={"OutputGroups": _output_groups(output_uri)},
        Tags={"purpose": "behavioral-check"},
    )["JobTemplate"]["Arn"]
    ctx.on_cleanup(lambda: mc.delete_job_template(Name=template_name))

    resp = _create_job_with_retry(
        mc,
        Role=role_arn,
        Queue=queue_name,
        JobTemplate=template_name,
        Settings={"Inputs": [{"FileInput": input_uri}]},
    )
    job_id = resp["Job"]["Id"]
    ctx.on_cleanup(lambda: mc.cancel_job(Id=job_id))

    # The terminal read must be independent of CreateJob's own response, so always issue at
    # least one GetJob; poll it within a bounded window in case JobTemplate lags behind.
    deadline = time.monotonic() + 30.0
    job = mc.get_job(Id=job_id)["Job"]
    while job.get("JobTemplate") is None and time.monotonic() < deadline:
        time.sleep(3.0)
        job = mc.get_job(Id=job_id)["Job"]

    assert job["JobTemplate"] in (
        template_name,
        template_arn,
    ), f"got JobTemplate={job.get('JobTemplate')!r}"
    output_groups = job["Settings"]["OutputGroups"]
    assert len(output_groups) == 1
    assert output_groups[0]["Name"] == "File Group"
    assert output_groups[0]["OutputGroupSettings"]["FileGroupSettings"]["Destination"] == output_uri
    assert output_groups[0]["Outputs"][0]["ContainerSettings"]["Container"] == "MP4"


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
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
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
