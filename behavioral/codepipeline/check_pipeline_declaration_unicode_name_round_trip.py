"""pipeline-declaration-unicode-name-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "pipeline-declaration-unicode-name-round-trip"
GROUP = "representation"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pipeline variable's defaultValue and description holding CJK, Cyrillic, accented Latin, Arabic and emoji
    text come back byte-identical from GetPipeline.
    """
    cp = ctx.client("codepipeline")
    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)
    pipeline_name = ctx.unique_name("sim2real-cp-uni-")

    default_value = "héllo-世界-Привет-🚀"
    description = "Ünïcödé désc — café ☕ 日本語 Ω مرحبا"

    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {
                        "S3Bucket": bucket,
                        "S3ObjectKey": "source/source.zip",
                        "PollForSourceChanges": "false",
                    },
                }
            ],
        },
        {
            "name": "Approve",
            "actions": [
                {
                    "name": "ApprovalAction",
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                }
            ],
        },
    ]

    decl = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
        "variables": [
            {"name": "GREETING", "defaultValue": default_value, "description": description},
        ],
    }

    _create_pipeline_with_retry(ctx, decl, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    fetched = cp.get_pipeline(name=pipeline_name)["pipeline"]
    fetched_vars = fetched["variables"]
    assert len(fetched_vars) == 1, f"expected 1 pipeline variable, got {len(fetched_vars)}: {fetched_vars!r}"
    assert fetched_vars[0]["defaultValue"] == default_value, (
        f"unicode defaultValue mangled: {fetched_vars[0]['defaultValue']!r} != {default_value!r}"
    )
    assert fetched_vars[0]["description"] == description, (
        f"unicode description mangled: {fetched_vars[0]['description']!r} != {description!r}"
    )


def _artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _pipeline_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-inline"))
    return role_arn


def _create_pipeline_with_retry(ctx, decl, tags=None, timeout_s=60.0):
    from botocore.exceptions import ClientError

    cp = ctx.client("codepipeline")
    kwargs = {"pipeline": decl}
    if tags is not None:
        kwargs["tags"] = tags
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cp.create_pipeline(**kwargs)["pipeline"]
        except ClientError as exc:
            # IAM role/trust policy propagation is eventually consistent, so a fresh
            # role can transiently fail CreatePipeline's own reference to it.
            if exc.response["Error"]["Code"] not in ("InvalidStructureException", "ValidationException"):
                raise
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreatePipeline never succeeded: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
