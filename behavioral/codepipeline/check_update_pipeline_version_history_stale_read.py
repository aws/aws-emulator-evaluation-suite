"""update-pipeline-version-history-stale-read."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipeline-version-history-stale-read"
GROUP = 'lifecycle'
SERVICES = ['codepipeline']


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val



def _purge_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _artifact_store(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cpart-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects LocationConstraint for us-east-1 itself
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _assumable_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cprole-")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="artifacts",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                           "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"))
    return role_arn


def _declaration(name, role_arn, bucket, *, gate_action_name):
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "AWS",
                                     "provider": "S3", "version": "1"},
                    "runOrder": 1,
                    "configuration": {"S3Bucket": bucket, "S3ObjectKey": "source.zip",
                                      "PollForSourceChanges": "false"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }],
            },
            {
                "name": "Gate",
                "actions": [{
                    "name": gate_action_name,
                    "actionTypeId": {"category": "Approval", "owner": "AWS",
                                     "provider": "Manual", "version": "1"},
                    "runOrder": 1,
                }],
            },
        ],
    }


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(
                pipeline=declaration, tags=[{"key": "sim2real", "value": CHECK}]
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _gate_action_name(cp, name, version=None):
    kw = {"name": name}
    if version is not None:
        kw["version"] = version
    pipeline = cp.get_pipeline(**kw)["pipeline"]
    return pipeline["version"], pipeline["stages"][1]["actions"][0]["name"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every UpdatePipeline increments pipeline.version, and GetPipeline with an explicit
    earlier `version` returns THAT version's structure, while a version that was never issued
    fails with PipelineVersionNotFoundException."""
    cp = ctx.client("codepipeline")
    bucket = _artifact_store(ctx)
    role_arn = _assumable_role(ctx, bucket)
    timeout_s = 180

    name = ctx.unique_name("sim2real-behav-cpver-")
    created = _create_with_role_propagation(
        cp, _declaration(name, role_arn, bucket, gate_action_name="GateV1"), timeout_s=timeout_s
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    assert created["pipeline"]["version"] == 1, (
        f"a freshly created pipeline must be version 1, got {created['pipeline']['version']!r}"
    )

    # One update -> version 2. UpdatePipeline takes the full declaration, so the only
    # difference is the approval action's name.
    updated = cp.update_pipeline(
        pipeline=_declaration(name, role_arn, bucket, gate_action_name="GateV2")
    )
    assert updated["pipeline"]["version"] == 2, (
        f"UpdatePipeline must increment pipeline.version 1 -> 2, got "
        f"{updated['pipeline']['version']!r}"
    )

    # A second update -> version 3, so a hardcoded "2" is caught.
    cp.update_pipeline(pipeline=_declaration(name, role_arn, bucket, gate_action_name="GateV3"))
    current = _poll(
        lambda: _gate_action_name(cp, name),
        lambda vn: vn[0] == 3 and vn[1] == "GateV3",
        timeout_s=timeout_s, interval_s=3,
    )
    assert current == (3, "GateV3"), (
        f"after two updates GetPipeline must report version 3 with action GateV3, got {current}"
    )

    # Stale reads must return the historical structure, not the current one.
    assert _gate_action_name(cp, name, version=1) == (1, "GateV1"), (
        f"GetPipeline(version=1) must return the original structure, got "
        f"{_gate_action_name(cp, name, version=1)} -- an emulator that discards history "
        f"returns the current declaration here"
    )
    assert _gate_action_name(cp, name, version=2) == (2, "GateV2"), (
        f"GetPipeline(version=2) must return the second structure, got "
        f"{_gate_action_name(cp, name, version=2)}"
    )

    # A version that was never issued must be refused, not clamped to the latest.
    try:
        clamped = cp.get_pipeline(name=name, version=99)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, message = err.get("Code"), err.get("Message", "")
    else:
        raise AssertionError(f"GetPipeline(version=99) succeeded instead of refusing: {clamped!r}")
    assert code == "PipelineVersionNotFoundException", (
        f"GetPipeline(version=99) returned {code!r}, expected "
        f"PipelineVersionNotFoundException (clamping to the latest version is the failure mode)"
    )
    account = role_arn.split(":")[4]
    expected = f"Account '{account}' does not have a pipeline with name '{name}' and version '99'."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
