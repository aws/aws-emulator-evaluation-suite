"""deploy-repository-lifecycle-policy-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-repository-lifecycle-policy-enforced"
GROUP = "deploy"
SERVICES = ["ecr"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RepoName:
    Type: String
Resources:
  Repo:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: !Ref RepoName
      LifecyclePolicy:
        LifecyclePolicyText: |
          {"rules":[{"rulePriority":1,"description":"keep only the newest image","selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":1},"action":{"type":"expire"}}]}
Outputs:
  RepoArn:
    Value: !GetAtt Repo.Arn
"""


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ECR::Repository with an attached LifecyclePolicy
    actually enforces its expiration rule: after pushing more images than the policy allows,
    a lifecycle policy preview marks the excess image(s) for expiry, not zero."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-lc-")

    _deploy_cfn(ctx, repo_name)

    # push two images; the deployed rule keeps only the single newest image (any tag status),
    # so exactly one of the two should be marked for expiry in a preview
    first = _push_image(ctx, repo_name, tag="v1")
    ctx.on_cleanup(lambda: _delete_all_images(ecr, repo_name))
    first_digest = first["imageId"]["imageDigest"]
    first_pushed_at = _pushed_at(ecr, repo_name, first_digest)

    # imagePushedAt must be distinguishable between the two pushes for the lifecycle rule's
    # "newest" ordering to be unambiguous; bound the retry on that observable read rather than
    # guessing how long real AWS's clock resolution needs.
    second = None
    deadline = time.monotonic() + 30.0
    while True:
        second = _push_image(ctx, repo_name, tag="v2")
        second_digest = second["imageId"]["imageDigest"]
        second_pushed_at = _pushed_at(ecr, repo_name, second_digest)
        if second_pushed_at != first_pushed_at:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"imagePushedAt stayed tied at {first_pushed_at!r} for both images "
                f"after 30s of retries; cannot establish a push-time ordering"
            )
        ecr.batch_delete_image(repositoryName=repo_name, imageIds=[second["imageId"]])
        time.sleep(1.0)
    assert first_digest != second_digest, (
        f"expected distinct image digests, both pushes reported {first_digest!r}"
    )

    ecr.start_lifecycle_policy_preview(repositoryName=repo_name)
    preview = _poll_until(
        lambda: ecr.get_lifecycle_policy_preview(repositoryName=repo_name),
        lambda resp: resp["status"] in ("COMPLETE", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert preview["status"] == "COMPLETE", f"expected COMPLETE, got {preview['status']!r}: {preview}"
    expiring_count = preview["summary"]["expiringImageTotalCount"]
    assert expiring_count == 1, f"expected exactly 1 expiring image, got {expiring_count}: {preview}"
    expiring_digests = {r["imageDigest"] for r in preview["previewResults"]}
    assert expiring_digests == {first_digest}, (
        f"expected only the older image {first_digest!r} to be marked for expiry, "
        f"got {expiring_digests!r}"
    )


import hashlib

_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _deploy_cfn(ctx, repo_name):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ecr-lc-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "RepoName", "ParameterValue": repo_name}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return stack_name


def _delete_stack(cfn, stack_name):
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _pushed_at(ecr, repo_name, digest):
    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageDigest": digest}])
    return resp["imageDetails"][0]["imagePushedAt"]


def _delete_all_images(ecr, repo_name):
    from botocore.exceptions import ClientError

    try:
        image_ids = ecr.list_images(repositoryName=repo_name)["imageIds"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise
        return
    if image_ids:
        ecr.batch_delete_image(repositoryName=repo_name, imageIds=image_ids)


def _upload_blob(ecr, repo_name, data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
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


def _push_image(ctx, repo_name, tag=None):
    ecr = ctx.client("ecr")
    unique = f"{repo_name}-{time.time_ns()}"
    config_bytes = json.dumps(
        {"architecture": "amd64", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}, "unique": unique}
    ).encode()
    layer_bytes = f"sim2real-ecr-layer-{unique}".encode()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": _MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": _CONFIG_MEDIA_TYPE, "size": len(config_bytes), "digest": config_digest},
        "layers": [{"mediaType": _LAYER_MEDIA_TYPE, "size": len(layer_bytes), "digest": layer_digest}],
    }
    kwargs = {"repositoryName": repo_name, "imageManifest": json.dumps(manifest)}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
