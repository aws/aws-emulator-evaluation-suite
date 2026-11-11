"""deploy-public-repository-cfn-behavior."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags

CHECK = "deploy-public-repository-cfn-behavior"
GROUP = "state-machine"
SERVICES = ["ecr-public"]


def _real_region_client(ctx, service: str):
    """A ctx client for ``service`` pinned to us-east-1, the only region serving ecr-public and
    AWS::ECR::PublicRepository."""
    return ctx.client(service, region="us-east-1")


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::ECR::PublicRepository stack yields a usable repository: DescribeRepositories finds
    it, an image pushes via layer upload + PutImage, and the token, layer and image reads work.
    """
    ecrpub = _real_region_client(ctx, "ecr-public")
    repo_name = ctx.unique_name("sim2real-ecrpub-cfn-")

    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "PubRepo": {
                    "Type": "AWS::ECR::PublicRepository",
                    "Properties": {"RepositoryName": repo_name},
                }
            },
        }
    )
    _deploy_cfn_stack(ctx, template_body)

    described = ecrpub.describe_repositories(repositoryNames=[repo_name])
    found_name = described["repositories"][0]["repositoryName"]
    assert found_name == repo_name, f"DescribeRepositories name mismatch: expected {repo_name!r}, got {found_name!r}"

    pushed = _push_test_image(ecrpub, repo_name, "cfn-pushed")
    image = pushed["image"]
    ctx.on_cleanup(
        lambda: ecrpub.batch_delete_image(
            repositoryName=repo_name, imageIds=[{"imageDigest": image["imageId"]["imageDigest"]}]
        )
    )
    pushed_tag = image["imageId"]["imageTag"]
    assert pushed_tag == "cfn-pushed", f"PutImage response tag mismatch: expected 'cfn-pushed', got {pushed_tag!r}"

    token_resp = ecrpub.get_authorization_token()
    auth_token = token_resp["authorizationData"]["authorizationToken"]
    assert auth_token, f"GetAuthorizationToken returned an empty token: {token_resp['authorizationData']!r}"

    avail = ecrpub.batch_check_layer_availability(
        repositoryName=repo_name,
        layerDigests=[f"sha256:{pushed['layer_digest']}", f"sha256:{pushed['config_digest']}"],
    )
    availability_by_digest = {
        layer["layerDigest"]: layer["layerAvailability"] for layer in avail["layers"]
    }
    layer_avail = availability_by_digest[f"sha256:{pushed['layer_digest']}"]
    assert layer_avail == "AVAILABLE", f"layer not AVAILABLE after push: expected 'AVAILABLE', got {layer_avail!r}"
    config_avail = availability_by_digest[f"sha256:{pushed['config_digest']}"]
    assert config_avail == "AVAILABLE", f"config layer not AVAILABLE after push: expected 'AVAILABLE', got {config_avail!r}"

    found = ecrpub.describe_images(repositoryName=repo_name)["imageDetails"]
    assert any(
        "cfn-pushed" in img.get("imageTags", []) for img in found
    ), f"pushed image not retrievable via DescribeImages: {found}"


def _deploy_cfn_stack(ctx, template_body: str) -> str:
    cfn = _real_region_client(ctx, "cloudformation")
    stack_name = ctx.unique_name("sim2real-ecrpub-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_cfn_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return stack_name


def _delete_cfn_stack(ctx, stack_name: str) -> None:
    cfn = _real_region_client(ctx, "cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25})  # fits the 60 s cleanup budget


def _upload_blob(client, repository_name: str, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    upload = client.initiate_layer_upload(repositoryName=repository_name)
    upload_id = upload["uploadId"]
    client.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    client.complete_layer_upload(
        repositoryName=repository_name,
        uploadId=upload_id,
        layerDigests=[f"sha256:{digest}"],
    )
    return digest


def _push_test_image(client, repository_name: str, tag: str) -> dict:
    layer_bytes = (f"sim2real-ecrpub-layer-{time.time_ns()}-").encode() * 64
    config_bytes = b'{"architecture":"amd64","os":"linux","config":{}}'
    layer_digest = _upload_blob(client, repository_name, layer_bytes)
    config_digest = _upload_blob(client, repository_name, config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": f"sha256:{config_digest}",
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": f"sha256:{layer_digest}",
            }
        ],
    }
    resp = client.put_image(
        repositoryName=repository_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
    )
    return {
        "image": resp["image"],
        "layer_digest": layer_digest,
        "config_digest": config_digest,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
