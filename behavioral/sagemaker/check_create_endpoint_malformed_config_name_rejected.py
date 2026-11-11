"""create-endpoint-malformed-config-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-endpoint-malformed-config-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint with a malformed EndpointConfigName and with a well-formed missing one each fails
    with ValidationException and its exact message, creating no endpoint, while the same call with a
    real config succeeds."""
    sm = ctx.client("sagemaker")

    # -- positive control: CreateEndpoint against a real, well-formed EndpointConfigName
    # succeeds, so the rejections below are shown to target the name specifically.
    role_arn = _create_sagemaker_role(ctx)
    model_name = ctx.unique_name("sim2real-sm-model-")
    image_uri = _push_check_image(ctx)[0]
    # CreateModel synchronously verifies the role can pull the container image; a
    # just-created role's IAM->ECR permission can take a few seconds to propagate, so
    # bounded retry on that call rather than a blind sleep.
    create_model_deadline = time.monotonic() + 30.0
    while True:
        try:
            sm.create_model(
                ModelName=model_name,
                ExecutionRoleArn=role_arn,
                PrimaryContainer={"Image": image_uri},
            )
            break
        except ClientError:
            if time.monotonic() >= create_model_deadline:
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    good_config_name = ctx.unique_name("sim2real-sm-epc-good-")
    sm.create_endpoint_config(
        EndpointConfigName=good_config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "ServerlessConfig": {"MemorySizeInMB": 1024, "MaxConcurrency": 1},
            }
        ],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=good_config_name))

    good_endpoint_name = ctx.unique_name("sim2real-sm-ep-control-")
    control_resp = sm.create_endpoint(
        EndpointName=good_endpoint_name, EndpointConfigName=good_config_name
    )
    ctx.on_cleanup(lambda: _delete_endpoint_when_settled(sm, good_endpoint_name))
    assert control_resp["EndpointArn"].endswith(f"endpoint/{good_endpoint_name}"), (
        f"expected CreateEndpoint against a real EndpointConfigName to succeed, "
        f"got {control_resp!r}"
    )

    # -- negative: EndpointConfigName contains characters outside [a-zA-Z0-9-]
    bad_endpoint_name = ctx.unique_name("sim2real-sm-ep-bad-")
    code, message = _error(
        lambda: sm.create_endpoint(
            EndpointName=bad_endpoint_name,
            EndpointConfigName="bad_config!name",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value 'bad_config!name' at 'endpointConfigName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-zA-Z0-9](-*[a-zA-Z0-9]){0,62}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no endpoint was ever created under that name
    not_found_code, not_found_message = _error(
        lambda: sm.describe_endpoint(EndpointName=bad_endpoint_name)
    )
    assert not_found_code == "ValidationException", (
        f"expected DescribeEndpoint on a never-created endpoint to fail with "
        f"ValidationException (EndpointName was never even accepted), got {not_found_code}"
    )
    expected_not_found = f'Could not find endpoint "{bad_endpoint_name}".'
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # -- distinguishing control: a well-formed EndpointConfigName that does not exist is also
    # rejected with ValidationException, but the message names the missing config: an existence
    # check, not the character-set rejection above.
    good_shape_endpoint_name = ctx.unique_name("sim2real-sm-ep-goodshape-")
    missing_config_name = ctx.unique_name("sim2real-sm-epc-missing-")
    missing_code, missing_message = _error(
        lambda: sm.create_endpoint(
            EndpointName=good_shape_endpoint_name,
            EndpointConfigName=missing_config_name,
        )
    )
    assert missing_code == "ValidationException", (
        f"expected ValidationException, got {missing_code}"
    )
    expected_missing = f'Could not find endpoint configuration "{missing_config_name}".'
    assert missing_message == expected_missing, (
        f"expected message {expected_missing!r}, got {missing_message!r}"
    )

    # effect absent: no endpoint was created under that name either
    not_found_code_2, not_found_message_2 = _error(
        lambda: sm.describe_endpoint(EndpointName=good_shape_endpoint_name)
    )
    assert not_found_code_2 == "ValidationException", (
        f"expected DescribeEndpoint on a never-created endpoint to fail with "
        f"ValidationException, got {not_found_code_2}"
    )
    expected_not_found_2 = f'Could not find endpoint "{good_shape_endpoint_name}".'
    assert not_found_message_2 == expected_not_found_2, (
        f"expected message {expected_not_found_2!r}, got {not_found_message_2!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # The image is a publicly-pullable AWS Deep Learning Container -- its own ECR
    # resource policy grants pull to every account, but the assumed role still needs
    # ecr:GetAuthorizationToken/BatchGetImage on its own side.
    ecr_policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn))

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1.0)
    return role_arn


def _delete_endpoint_when_settled(sm, endpoint_name, timeout_s=900.0, interval_s=2.0):
    """DeleteEndpoint refuses an endpoint that is still Creating/Updating, so wait for a
    settled status (bounded, raising on timeout) and then delete; an endpoint that is
    already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = sm.describe_endpoint(EndpointName=endpoint_name)["EndpointStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                return
            raise
        if status not in ("Creating", "Updating", "SystemUpdating", "RollingBack", "Deleting"):
            break
        if status == "Deleting":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"endpoint {endpoint_name} still {status} after {timeout_s}s")
        time.sleep(interval_s)
    sm.delete_endpoint(EndpointName=endpoint_name)


def _push_check_image(ctx, tags=("v1",)) -> list[str]:
    """Push a minimal image to a check-owned ECR repository under each tag; return the image URIs.
    SageMaker resolves the image at create time, so it must exist; no inference is served from it."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-sm-repo-").lower()
    repo_uri = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["repository"]["repositoryUri"]
    ctx.on_cleanup(lambda: _delete_check_repository(ecr, repo_name))
    for tag in tags:
        _push_minimal_image(ecr, repo_name, tag)
    return [f"{repo_uri}:{tag}" for tag in tags]


def _delete_check_repository(ecr, repo_name) -> None:
    """Force-delete the repository; RepositoryNotFoundException means already gone, the rest raises."""
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal empty-layer Docker v2 image via the ECR API, without a Docker daemon."""
    import gzip
    import hashlib
    import io
    import tarfile

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    tar_bytes = tar_buf.getvalue()
    diff_id = hashlib.sha256(tar_bytes).hexdigest()

    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    layer_bytes = gz_buf.getvalue()
    layer_digest = hashlib.sha256(layer_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]},
    }
    config_bytes = json.dumps(config).encode()
    config_digest = hashlib.sha256(config_bytes).hexdigest()

    def _upload_blob(blob: bytes, digest: str) -> None:
        upload = ecr.initiate_layer_upload(repositoryName=repo_name)
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload["uploadId"],
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        try:
            ecr.complete_layer_upload(
                repositoryName=repo_name,
                uploadId=upload["uploadId"],
                layerDigests=[f"sha256:{digest}"],
            )
        except ClientError as exc:
            # Identical (e.g. empty) layer content may already exist in the repo.
            if exc.response["Error"]["Code"] != "LayerAlreadyExistsException":
                raise

    _upload_blob(layer_bytes, layer_digest)
    _upload_blob(config_bytes, config_digest)

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
    ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

