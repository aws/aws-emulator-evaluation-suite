"""ecr-cross-account-pull-denied-without-repo-policy-rejected."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from behavioral_harness import tags

CHECK = "ecr-cross-account-pull-denied-without-repo-policy-rejected"
GROUP = "image-pull"
SERVICES = ["ecr", "eks", "logs"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role with no ECR pull permission is denied BatchGetImage with the exact AccessDenied message,
    then can pull once a repository policy grants it, as a cross-account consumer would."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    ecr = ctx.client("ecr")

    account_id = sts.get_caller_identity()["Account"]

    repo_name = ctx.unique_name("sim2real-xacct-repo-")
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    tag = "sim2real-test"
    _push_scratch_image(ecr, repo_name, tag)

    # A same-account role with no identity-based pull grant stands in for the external principal.
    consumer_name = ctx.unique_name("sim2real-xacct-consumer-")
    consumer_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    consumer_role_arn = iam.create_role(
        RoleName=consumer_name,
        AssumeRolePolicyDocument=json.dumps(consumer_trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=consumer_name))
    # Only the account-level auth action -- deliberately NO BatchGetImage/GetDownloadUrlForLayer.
    iam.put_role_policy(
        RoleName=consumer_name,
        PolicyName="ecr-auth-only",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=consumer_name, PolicyName="ecr-auth-only"))

    consumer_ecr = _assume_role_client(ctx, consumer_role_arn, "ecr")

    # Positive control: the account-owning caller can already see the pushed image.
    owner_check = ecr.batch_get_image(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
    assert len(owner_check["images"]) == 1, "image push did not land -- can't isolate the permission boundary"

    # Negative: no repository policy grant + no identity permission -> denied.
    code_before, message_before = _error(
        lambda: consumer_ecr.batch_get_image(
            repositoryName=repo_name, registryId=account_id, imageIds=[{"imageTag": tag}]
        )
    )
    assert code_before == "AccessDeniedException", f"expected AccessDeniedException, got {code_before!r}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{consumer_name}/sim2real-xacct is not "
        f"authorized to perform: ecr:BatchGetImage on resource: "
        f"arn:aws:ecr:{ctx.region}:{account_id}:repository/{repo_name} because no "
        "identity-based policy allows the ecr:BatchGetImage action"
    )
    assert message_before == expected, f"expected message {expected!r}, got {message_before!r}"

    # Grant the consumer role access purely via the repository (resource-based) policy, mirroring
    # what a cross-account grant would add to a repository owned by another account.
    ecr.set_repository_policy(
        repositoryName=repo_name,
        policyText=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowConsumerRolePull",
                        "Effect": "Allow",
                        "Principal": {"AWS": consumer_role_arn},
                        "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: ecr.delete_repository_policy(repositoryName=repo_name))

    resp = _poll_until_allowed(
        lambda: consumer_ecr.batch_get_image(
            repositoryName=repo_name, registryId=account_id, imageIds=[{"imageTag": tag}]
        ),
        timeout_s=60.0,
    )
    assert len(resp["images"]) == 1, "consumer role still could not pull the image after the repo policy grant"



def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be denied, but it succeeded: {result!r}")


def _poll_until_allowed(fn, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_err}")


def _assume_role_client(ctx, role_arn, service, timeout_s=45.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-xacct")["Credentials"]
            break
        except ClientError as err:
            # IAM trust-policy propagation: the role was just created and is not yet assumable.
            last_err = err
            time.sleep(interval_s)
    if creds is None:
        raise AssertionError(f"role {role_arn} never became assumable within {timeout_s}s: {last_err}")
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _build_scratch_image_blobs():
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    uncompressed = tar_buf.getvalue()
    diff_id = "sha256:" + hashlib.sha256(uncompressed).hexdigest()
    compressed = gzip.compress(uncompressed)
    layer_digest = "sha256:" + hashlib.sha256(compressed).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Cmd": ["/bin/true"]},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": "2024-01-01T00:00:00Z"}],
    }
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    return compressed, layer_digest, config_bytes, config_digest


def _upload_blob(ecr, repo_name, blob, digest):
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])


def _push_scratch_image(ecr, repo_name, tag):
    compressed, layer_digest, config_bytes, config_digest = _build_scratch_image_blobs()
    _upload_blob(ecr, repo_name, compressed, layer_digest)
    _upload_blob(ecr, repo_name, config_bytes, config_digest)
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
                "size": len(compressed),
                "digest": layer_digest,
            }
        ],
    }
    ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
        imageManifestMediaType=manifest["mediaType"],
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
