"""deploy-registry-scanning-configuration-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-registry-scanning-configuration-enforced"
GROUP = "deploy"
SERVICES = ["ecr"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RepoPrefix:
    Type: String
Resources:
  ScanConfig:
    Type: AWS::ECR::RegistryScanningConfiguration
    Properties:
      ScanType: BASIC
      Rules:
        - RepositoryFilters:
            - Filter: !Sub "${RepoPrefix}*"
              FilterType: WILDCARD
          ScanFrequency: SCAN_ON_PUSH
"""

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ECR::RegistryScanningConfiguration with SCAN_ON_PUSH makes a
    push to a matching repository start a scan that reaches a terminal status."""
    ecr = ctx.client("ecr")
    # The registry scanning configuration is an account-wide singleton; restore it afterwards.
    original_config = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    ctx.on_cleanup(lambda: _restore_scanning_configuration(ecr, original_config))

    repo_prefix = ctx.unique_name("sim2real-ecr-scan-")
    repo = _create_repo(ctx, repo_prefix)

    _deploy_cfn(ctx, repo_prefix)

    pushed = _push_image(ctx, repo["repositoryName"], tag="scan-me")

    # ScanNotFoundException is raised until the scan starts.
    findings = _poll_until(
        lambda: _try_describe_findings(ecr, repo["repositoryName"], pushed["imageId"]["imageDigest"]),
        lambda resp: resp is not None
        and resp["imageScanStatus"]["status"] not in ("PENDING", "IN_PROGRESS"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    scan_status = findings["imageScanStatus"]
    # the synthetic image carries no OS or package manager, so basic scanning completes
    # its run and reports the image as unsupported
    expected = {
        "status": "FAILED",
        "description": "UnsupportedImageError: The operating system and/or package manager are not supported.",
    }
    assert scan_status == expected, f"expected imageScanStatus {expected!r}, got {scan_status!r}"


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


def _try_describe_findings(ecr, repo_name, digest):
    from botocore.exceptions import ClientError

    try:
        return ecr.describe_image_scan_findings(repositoryName=repo_name, imageId={"imageDigest": digest})
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ScanNotFoundException":
            return None
        raise


def _create_repo(ctx, prefix):
    ecr = ctx.client("ecr")
    name = f"{prefix}sample"
    resp = ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _restore_scanning_configuration(ecr, config):
    ecr.put_registry_scanning_configuration(
        scanType=config["scanType"], rules=config.get("rules", [])
    )


def _deploy_cfn(ctx, repo_prefix):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ecr-scan-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "RepoPrefix", "ParameterValue": repo_prefix}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return stack_name


def _delete_stack(cfn, stack_name):
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


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
