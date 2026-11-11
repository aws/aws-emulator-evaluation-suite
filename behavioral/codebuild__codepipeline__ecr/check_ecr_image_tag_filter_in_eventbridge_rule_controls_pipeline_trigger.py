"""ecr-image-tag-filter-in-eventbridge-rule-controls-pipeline-trigger."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecr-image-tag-filter-in-eventbridge-rule-controls-pipeline-trigger"
GROUP = "event-propagation"
SERVICES = ["codebuild", "codepipeline", "ecr"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule filtered on a specific "image-tag" only starts the pipeline for
    pushes carrying that exact tag; a push of a different tag to the same repository is
    filtered out and never starts an execution."""
    cp = ctx.client("codepipeline")
    ecr = ctx.client("ecr")

    bucket = _create_artifact_bucket(ctx)
    repo_name = _create_ecr_repo(ctx)
    pipeline_role_arn = _create_service_role(
        ctx,
        "codepipeline.amazonaws.com",
        "cp-role",
        [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {"Effect": "Allow", "Action": ["ecr:DescribeImages"], "Resource": "*"},
        ],
    )
    matched_tag = "prod-release"
    pipeline_name, pipeline_arn = _create_pipeline(ctx, pipeline_role_arn, bucket, repo_name, matched_tag)
    baseline_ids = _snapshot_after_initial_execution(cp, pipeline_name)

    eb_role_arn = _create_service_role(
        ctx,
        "events.amazonaws.com",
        "eb-role",
        [{"Effect": "Allow", "Action": "codepipeline:StartPipelineExecution", "Resource": pipeline_arn}],
    )
    _create_ecr_push_rule(ctx, repo_name, pipeline_arn, eb_role_arn, image_tag_filter=matched_tag)

    # Mismatched tag: the rule's image-tag filter must exclude this push.
    _push_ecr_image(ecr, repo_name, "dev-build")
    _assert_no_new_execution(
        cp,
        pipeline_name,
        baseline_ids,
        timeout_s=60.0,
        description="pipeline started by a push whose image-tag does not match the rule filter",
    )

    # Matching tag: the same rule must now trigger the pipeline. Tie the accepted execution to
    # this specific push's image digest (not just "any id beyond baseline") so a wrong-tag
    # execution that was merely slow to register (racing past the 60s window above) cannot be
    # mistaken for the correct trigger.
    matched_digest = _push_ecr_image(ecr, repo_name, matched_tag)
    new_id = _wait_for_new_execution_id(cp, pipeline_name, baseline_ids, timeout_s=150.0)
    assert new_id and new_id not in baseline_ids
    triggering_revision = _source_revision_id(cp, pipeline_name, new_id)
    assert triggering_revision == matched_digest, (
        f"execution {new_id} was triggered by revision {triggering_revision!r}, "
        f"not the matching-tag push's digest {matched_digest!r} -- the new execution may be a "
        f"delayed trigger from the earlier mismatched-tag push rather than the filter correctly "
        f"admitting this push"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retry_on_iam_propagation(fn, timeout_s=60.0, interval_s=3.0):
    """Retry fn() on ClientError to absorb IAM role-creation eventual consistency (a role handed
    to another service moments after CreateRole can transiently fail to be assumed/validated)."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _create_service_role(ctx, principal, prefix, policy_statements):
    """Create an IAM role trusted by `principal` with an inline policy; registers teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-{prefix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if policy_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="perms",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="perms"))
    return arn


def _create_artifact_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-artifacts-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        versions = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_ecr_repo(ctx):
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-repo-")
    ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _upload_ecr_blob(ecr, repo_name, data):
    digest = "sha256:" + _sha256_hex(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _push_ecr_image(ecr, repo_name, tag):
    """Push a minimal but structurally valid Docker v2 manifest image via the ECR data-plane
    layer-upload + PutImage APIs (no docker daemon required); returns the resulting image digest."""
    unique = f"{tag}-{time.time_ns()}"
    config_blob = json.dumps(
        {"architecture": "amd64", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}, "nonce": unique}
    ).encode()
    layer_blob = f"sim2real-layer-{unique}".encode()
    config_digest = _upload_ecr_blob(ecr, repo_name, config_blob)
    layer_digest = _upload_ecr_blob(ecr, repo_name, layer_blob)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_blob),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_blob),
                "digest": layer_digest,
            }
        ],
    }
    resp = ecr.put_image(
        repositoryName=repo_name,
        imageTag=tag,
        imageManifest=json.dumps(manifest),
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
    )
    return resp["image"]["imageId"]["imageDigest"]


def _create_pipeline(ctx, role_arn, bucket, repo_name, image_tag):
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-pipeline-")
    structure = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "Source",
                        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "ECR", "version": "1"},
                        "outputArtifacts": [{"name": "SourceArtifact"}],
                        "configuration": {"RepositoryName": repo_name, "ImageTag": image_tag},
                    }
                ],
            },
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "Approve",
                        "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                        "configuration": {},
                    }
                ],
            },
        ],
    }
    _retry_on_iam_propagation(
        lambda: cp.create_pipeline(pipeline=structure, tags=[{"key": "sim2real", "value": CHECK}])
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    pipeline_arn = f"arn:aws:codepipeline:{ctx.region}:{account_id}:{name}"
    return name, pipeline_arn


def _create_ecr_push_rule(ctx, repo_name, pipeline_arn, role_arn, image_tag_filter=None):
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-ecr-rule-")
    detail = {"action-type": ["PUSH"], "repository-name": [repo_name], "result": ["SUCCESS"]}
    if image_tag_filter:
        detail["image-tag"] = [image_tag_filter]
    pattern = {"source": ["aws.ecr"], "detail-type": ["ECR Image Action"], "detail": detail}
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    target_id = "1"
    resp = events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": pipeline_arn, "RoleArn": role_arn}])
    if resp.get("FailedEntryCount", 0):
        raise AssertionError(f"put_targets failed for rule {rule_name}: {resp.get('FailedEntries')}")
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))
    return rule_name


def _list_execution_ids(cp, pipeline_name):
    resp = cp.list_pipeline_executions(pipelineName=pipeline_name, maxResults=100)
    return {s["pipelineExecutionId"] for s in resp.get("pipelineExecutionSummaries", [])}


def _source_revision_id(cp, pipeline_name, execution_id):
    """The ECR source action's revisionId (the image digest) for a given execution."""
    execution = cp.get_pipeline_execution(
        pipelineName=pipeline_name, pipelineExecutionId=execution_id
    )["pipelineExecution"]
    revisions = execution["artifactRevisions"]
    assert revisions, f"execution {execution_id} has no artifactRevisions to identify its trigger"
    return revisions[0]["revisionId"]


def _snapshot_after_initial_execution(cp, pipeline_name, timeout_s=60.0):
    """CreatePipeline auto-starts an initial execution; wait for it to register so the baseline
    snapshot doesn't race with it (which would make a later, unrelated execution look "new")."""
    return _poll_until(
        lambda: _list_execution_ids(cp, pipeline_name),
        lambda ids: len(ids) >= 1,
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"initial execution registered on pipeline {pipeline_name}",
    )


def _wait_for_new_execution_id(cp, pipeline_name, baseline_ids, timeout_s=150.0):
    result = _poll_until(
        lambda: _list_execution_ids(cp, pipeline_name),
        lambda ids: bool(ids - baseline_ids),
        timeout_s=timeout_s,
        interval_s=4.0,
        description=f"new execution on pipeline {pipeline_name}",
    )
    return next(iter(result - baseline_ids))


def _assert_no_new_execution(
    cp, pipeline_name, baseline_ids, timeout_s=60.0, interval_s=3.0, description="unexpected pipeline execution"
):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        extra = _list_execution_ids(cp, pipeline_name) - baseline_ids
        if extra:
            raise AssertionError(f"{description}: unexpected execution(s) {extra} appeared")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
