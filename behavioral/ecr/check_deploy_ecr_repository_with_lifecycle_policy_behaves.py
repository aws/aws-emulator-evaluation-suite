"""deploy-ecr-repository-with-lifecycle-policy-behaves."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-ecr-repository-with-lifecycle-policy-behaves"
GROUP = "deploy"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ECR::Repository with an inline lifecycle policy actually
    enforces image expiration once a real image is pushed, verified through a lifecycle
    policy preview against that image -- not merely stack CREATE_COMPLETE."""
    ecr = ctx.client("ecr")
    cfn = ctx.client("cloudformation")

    repo_name = ctx.unique_name("sim2real-ecr-cfn-lp-").lower()
    stack_name = ctx.unique_name("sim2real-ecr-cfn-lp-stack-")

    lifecycle_policy = {
        "rules": [
            {
                "rulePriority": 1,
                "description": "sim2real test rule: keep only the newest tagged 'old*' image, expire the rest",
                "selection": {
                    "tagStatus": "tagged",
                    "tagPrefixList": ["old"],
                    "countType": "imageCountMoreThan",
                    "countNumber": 1,
                },
                "action": {"type": "expire"},
            }
        ]
    }
    template = {
        "Resources": {
            "Repo": {
                "Type": "AWS::ECR::Repository",
                "Properties": {
                    "RepositoryName": repo_name,
                    "EmptyOnDelete": True,
                    "LifecyclePolicy": {
                        "LifecyclePolicyText": json.dumps(lifecycle_policy),
                    },
                },
            }
        },
        "Outputs": {"RepoName": {"Value": {"Ref": "Repo"}}},
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real-owner", "Value": repo_name}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))

    stack = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        lambda s: s["StackStatus"] in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack.get("StackStatusReason")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    deployed_repo_name = outputs["RepoName"]
    assert deployed_repo_name == repo_name, f"expected {repo_name!r}, got {deployed_repo_name!r}"

    # Confirm the lifecycle policy CloudFormation attached is actually the one stored/enforced.
    stored_policy = json.loads(
        ecr.get_lifecycle_policy(repositoryName=deployed_repo_name)["lifecyclePolicyText"]
    )
    assert stored_policy == lifecycle_policy, f"expected {lifecycle_policy!r}, got {stored_policy!r}"

    # Push "old-build-1", then push "old-build-2" only once its own reported pushedAt is
    # confirmably later than old-build-1's -- the newest-wins tiebreak the rule depends on.
    # A blind sleep cannot guarantee ordering; this bounds the wait and verifies the invariant
    # the assertion below actually needs, per the target's own reported timestamps.
    first_pushed_at = _push_and_get_pushed_at(ecr, deployed_repo_name, "old-build-1")
    second_pushed_at = _poll_until(
        lambda: _push_and_get_pushed_at(ecr, deployed_repo_name, "old-build-2"),
        lambda pushed_at: pushed_at > first_pushed_at,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert second_pushed_at > first_pushed_at, (
        f"expected old-build-2 pushedAt > old-build-1 pushedAt "
        f"({first_pushed_at!r}), got {second_pushed_at!r}"
    )

    ecr.start_lifecycle_policy_preview(repositoryName=deployed_repo_name)
    preview = _poll_until(
        lambda: ecr.get_lifecycle_policy_preview(repositoryName=deployed_repo_name),
        lambda p: p["status"] in ("COMPLETE", "FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert preview["status"] == "COMPLETE", preview
    expiring = [
        r
        for r in preview["previewResults"]
        if "old-build-1" in r.get("imageTags", []) and r["action"]["type"] == "EXPIRE"
    ]
    assert expiring, f"expected old-build-1 to be marked EXPIRE, got {preview['previewResults']}"
    kept = [
        r
        for r in preview["previewResults"]
        if "old-build-2" in r.get("imageTags", []) and r["action"]["type"] == "EXPIRE"
    ]
    assert not kept, f"expected old-build-2 (newest) to be kept, got {preview['previewResults']}"


def _delete_stack_and_wait(cfn, stack_name) -> None:
    from botocore.exceptions import ClientError

    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not stacks:
            return
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(
                f"stack {stack_name} failed to tear down: {stacks[0].get('StackStatusReason')}"
            )
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within 180s")


def _empty_gzip_tar_blob() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass
    return buf.getvalue()


def _push_minimal_image(ecr, repo_name: str, tag: str) -> str:
    layer_bytes = _empty_gzip_tar_blob()
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    config_obj = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Labels": {"sim2real-nonce": str(uuid.uuid4())}},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    }
    config_bytes = json.dumps(config_obj).encode("utf-8")
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()

    for blob, digest in ((config_bytes, config_digest), (layer_bytes, layer_digest)):
        upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        try:
            ecr.complete_layer_upload(
                repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
            )
        except ecr.exceptions.LayerAlreadyExistsException:
            pass

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    put_response = ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
    )
    return put_response["image"]["imageId"]["imageDigest"]


def _push_and_get_pushed_at(ecr, repo_name: str, tag: str):
    _push_minimal_image(ecr, repo_name, tag)
    detail = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": tag}])[
        "imageDetails"
    ][0]
    return detail["imagePushedAt"]


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s, last value={value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
