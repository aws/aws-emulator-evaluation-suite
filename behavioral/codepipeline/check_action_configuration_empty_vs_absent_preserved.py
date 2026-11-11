"""action-configuration-empty-vs-absent-preserved."""
from __future__ import annotations

import copy
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "action-configuration-empty-vs-absent-preserved"
GROUP = "server-side"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePipeline replaces an action's configuration map: an empty-string CustomData (sent past client-side
    validation) fails with ValidationException and its exact message, while adding and removing the key
    round-trip through GetPipeline.
    """
    from botocore.config import Config

    cp = ctx.client("codepipeline")
    role_arn = _create_pipeline_role(ctx)
    bucket = _create_bucket(ctx, versioning=True)
    ctx.client("s3").put_object(Bucket=bucket, Key="src.txt", Body=b"x")

    name = ctx.unique_name("sim2real-cp-pipe-")
    _create_pipeline_with_retry(
        cp,
        {
            "name": name,
            "roleArn": role_arn,
            "artifactStore": {"type": "S3", "location": bucket},
            "stages": _minimal_stages(bucket, "src.txt", approval_config={}),
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    fetched = cp.get_pipeline(name=name)["pipeline"]
    approval_action = fetched["stages"][1]["actions"][0]
    assert "CustomData" not in approval_action.get("configuration", {}), (
        f"expected no CustomData key on a freshly created pipeline, got {approval_action.get('configuration')!r}"
    )

    # An empty-string configuration value is rejected by boto3's OWN client-side parameter
    # validation (a shared min-length-1 constraint on every configuration value) before a
    # request is even built -- so asserting on that ParamValidationError would test botocore,
    # never the target. Reach the real SERVICE's verdict on the same empty-string value over
    # the wire instead, through a client built via ctx.client() (so it stays wired to the
    # correct endpoint/credentials on both real AWS and an emulator) with parameter validation
    # switched off -- it skips botocore's local schema check but still sends a real, signed
    # request.
    raw_cp = ctx.client(
        "codepipeline",
        config=Config(parameter_validation=False, retries={"max_attempts": 8, "mode": "standard"}),
    )
    with_empty_wire = copy.deepcopy(fetched)
    with_empty_wire["stages"][1]["actions"][0]["configuration"] = {"CustomData": ""}
    code, message = _error(lambda: raw_cp.update_pipeline(pipeline=with_empty_wire))
    assert code == "ValidationException", f"unexpected service-side verdict on empty string: {code!r}"
    assert message == (
        "1 validation error detected: Value at 'pipeline.stages.2.member.actions.1.member.configuration' "
        "failed to satisfy constraint: Map value must satisfy constraint: "
        "[Member must have length less than or equal to 50000, Member must have length greater than or equal to 1]"
    ), f"unexpected service-side message on empty string: {message!r}"

    # Effect absent: the real action configuration is untouched by the rejected update.
    unaffected = cp.get_pipeline(name=name)["pipeline"]["stages"][1]["actions"][0]
    assert "CustomData" not in unaffected.get("configuration", {}), (
        f"rejected empty-string update still mutated the configuration: {unaffected.get('configuration')!r}"
    )

    # absent -> present-with-real-value via UpdatePipeline (positive control for the
    # add/remove machinery the empty-string case couldn't exercise end-to-end).
    with_key = copy.deepcopy(fetched)
    with_key["stages"][1]["actions"][0]["configuration"] = {"CustomData": "now-present"}
    cp.update_pipeline(pipeline=with_key)

    after_add = cp.get_pipeline(name=name)["pipeline"]
    added_action = after_add["stages"][1]["actions"][0]
    assert added_action["configuration"]["CustomData"] == "now-present", (
        f"expected CustomData='now-present', got {added_action.get('configuration')!r}"
    )

    # present -> entirely absent again.
    without_key = copy.deepcopy(after_add)
    without_key["stages"][1]["actions"][0]["configuration"] = {}
    cp.update_pipeline(pipeline=without_key)

    after_remove = cp.get_pipeline(name=name)["pipeline"]
    removed_action = after_remove["stages"][1]["actions"][0]
    assert "CustomData" not in removed_action.get("configuration", {}), (
        f"expected CustomData removed after clearing configuration, got {removed_action.get('configuration')!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _create_pipeline_with_retry(cp, pipeline: dict, tags=None, attempts: int = 6, delay_s: float = 5.0) -> dict:
    """CreatePipeline can transiently fail with InvalidStructureException /
    ValidationException while the just-created IAM role's trust policy propagates."""
    from botocore.exceptions import ClientError

    kwargs = {"pipeline": pipeline}
    if tags:
        kwargs["tags"] = tags
    last_err = None
    for _ in range(attempts):
        try:
            return cp.create_pipeline(**kwargs)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _create_pipeline_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cp-policy-")
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_bucket(ctx, versioning: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-").lower()
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    if versioning:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _minimal_stages(source_bucket, source_key, approval_action_name="Approve", approval_config=None):
    return [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                    "configuration": {
                        "S3Bucket": source_bucket,
                        "S3ObjectKey": source_key,
                        "PollForSourceChanges": "false",
                    },
                    "outputArtifacts": [{"name": "SourceArtifact"}],
                }
            ],
        },
        {
            "name": "Approval",
            "actions": [
                {
                    "name": approval_action_name,
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                    "configuration": approval_config or {},
                }
            ],
        },
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
