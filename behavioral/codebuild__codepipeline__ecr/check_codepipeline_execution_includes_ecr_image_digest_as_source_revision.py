"""codepipeline-execution-includes-ecr-image-digest-as-source-revision."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "codepipeline-execution-includes-ecr-image-digest-as-source-revision"
GROUP = "event-propagation"
SERVICES = ["codebuild", "codepipeline", "ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """The pipeline execution an ECR push triggers records the exact image digest of that push
    as its Source action's source revision -- not a stale digest carried over from an earlier
    push to the same tag."""
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
    tag = "revtest"
    pipeline_name, pipeline_arn = _create_pipeline(ctx, pipeline_role_arn, bucket, repo_name, tag)
    baseline_ids = _snapshot_after_initial_execution(cp, pipeline_name)

    eb_role_arn = _create_service_role(
        ctx,
        "events.amazonaws.com",
        "eb-role",
        [{"Effect": "Allow", "Action": "codepipeline:StartPipelineExecution", "Resource": pipeline_arn}],
    )
    _create_ecr_push_rule(ctx, repo_name, pipeline_arn, eb_role_arn, image_tag_filter=tag)

    # The newly-created EventBridge invoke role needs time to propagate through IAM before the
    # rule's target can assume it. That window isn't independently observable (get_role returns
    # immediately regardless), so instead of guessing a fixed delay, re-push on a bounded deadline
    # until a push actually triggers an execution -- self-healing if an early attempt's invocation
    # is dropped while the role is still propagating.
    digest_1, exec_id_1, ids_after_1 = _push_until_triggered(ecr, cp, pipeline_name, repo_name, tag, baseline_ids)

    digest_2, exec_id_2, _ids_after_2 = _push_until_triggered(ecr, cp, pipeline_name, repo_name, tag, ids_after_1)
    assert digest_2 != digest_1, "test setup produced two identical image digests"

    rev_1 = _source_revision_id(cp, pipeline_name, exec_id_1)
    rev_2 = _source_revision_id(cp, pipeline_name, exec_id_2)
    assert rev_1 == digest_1, f"execution {exec_id_1} source revision {rev_1} != pushed digest {digest_1}"
    assert rev_2 == digest_2, f"execution {exec_id_2} source revision {rev_2} != pushed digest {digest_2}"


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


def _push_until_triggered(ecr, cp, pipeline_name, repo_name, tag, baseline_ids, *, deadline_s=120.0, attempt_timeout_s=20.0):
    """Push a fresh image and wait for a new execution; if none appears within attempt_timeout_s
    (e.g. the EventBridge invoke role hadn't finished propagating yet), push again -- each push is
    a fresh event, so this self-heals instead of trusting a fixed delay. Returns the digest of
    whichever push is confirmed to have triggered, the new execution id, and the updated id set."""
    deadline = time.monotonic() + deadline_s
    while True:
        digest = _push_ecr_image(ecr, repo_name, tag)
        attempt_deadline = min(time.monotonic() + attempt_timeout_s, deadline)
        while time.monotonic() < attempt_deadline:
            ids = _list_execution_ids(cp, pipeline_name)
            new_ids = ids - baseline_ids
            if new_ids:
                return digest, next(iter(new_ids)), ids
            time.sleep(4.0)
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no new execution on pipeline {pipeline_name} triggered by any push to "
                f"{repo_name}:{tag} within {deadline_s}s"
            )


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


def _source_revision_id(cp, pipeline_name, execution_id):
    resp = cp.list_pipeline_executions(pipelineName=pipeline_name, maxResults=100)
    for summary in resp.get("pipelineExecutionSummaries", []):
        if summary["pipelineExecutionId"] == execution_id:
            for rev in summary.get("sourceRevisions", []):
                if rev.get("actionName") == "Source":
                    return rev.get("revisionId")
    raise AssertionError(f"no source revision found for execution {execution_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
