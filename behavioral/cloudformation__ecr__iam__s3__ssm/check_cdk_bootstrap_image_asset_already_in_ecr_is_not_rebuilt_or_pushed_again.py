"""cdk-bootstrap-image-asset-already-in-ecr-is-not-rebuilt-or-pushed-again."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-bootstrap-image-asset-already-in-ecr-is-not-rebuilt-or-pushed-again"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam", "s3", "ssm"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 300.0
_SHOW_TEMPLATE_TIMEOUT_S = 60.0
# A cdk step ends this long before the runner's budget, so it fails with its own message.
_RESERVE_S = 15.0
_POLL_S = 5.0
_TEARDOWN_DEADLINE_S = 420.0

# The five roles the bootstrap template names `cdk-<qualifier>-<role>-<account>-<region>`.
_ROLES = (
    "cfn-exec-role",
    "deploy-role",
    "file-publishing-role",
    "image-publishing-role",
    "lookup-role",
)
_ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
# The template's `Ref: AWS::NoValue`: the property or list item is left out.
_NO_VALUE = object()
# The template's SSE-KMS default with the AWS managed key; it sets no S3 Bucket Key.
_KMS_DEFAULT_RULES = [
    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": False}
]

_IMAGE_APP_PY = """\
import aws_cdk as cdk
from aws_cdk import aws_ecr_assets as ecr_assets

app = cdk.App()
stack = cdk.Stack(app, app.node.get_context("stack_name"))
ecr_assets.DockerImageAsset(stack, "image", directory="image")
# A stack with no resource is never deployed, so its assets are never published.
cdk.CfnResource(stack, "Handle", type="AWS::CloudFormation::WaitConditionHandle")
app.synth()
"""

# The asset's build context; the CLI hashes it into the asset id and builds it only when the
# repository lacks that tag.
_DOCKERFILE = "FROM scratch\nCOPY marker.txt /marker.txt\n"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A Docker image asset whose tag is already in the bootstrap repository is not built or pushed.

    The deploy finds the tag through the image-publishing role and runs as the exec role; ECR still
    holds only the image already under the tag, with its digest and push time unchanged.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/assets.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")
    ecr = ctx.client("ecr")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    app_stack = ctx.unique_name("sim2real-cdkimage-")
    names = _toolkit_names(ctx, qualifier)
    exec_arn = f"arn:aws:iam::{ctx.account}:role/{names['cfn-exec-role']}"
    template = _bootstrap_template(ctx)
    work = _stage_app(
        ctx,
        {
            "app.py": _IMAGE_APP_PY,
            "image/Dockerfile": _DOCKERFILE,
            "image/marker.txt": ctx.unique_name("marker-"),
        },
    )
    context = {
        "stack_name": app_stack,
        "@aws-cdk/core:bootstrapQualifier": qualifier,
        "@aws-cdk/core:newStyleStackSynthesis": "1",
    }

    ctx.on_cleanup(lambda: _teardown(ctx, toolkit_stack, qualifier, app_stacks=[app_stack]))
    _bootstrap(
        ctx,
        toolkit_stack,
        ["--qualifier", qualifier, "--cloudformation-execution-policies", _ADMIN],
    )

    # 1. synthesis names the asset tag, the bootstrap repository and the image-publishing role
    _cdk(ctx, work, ["synth", app_stack], context)
    asset_id, destination = _image_destination(ctx, work, app_stack)
    publisher = f"arn:aws:iam::{ctx.account}:role/{names['image-publishing-role']}"
    want = {
        "repositoryName": names["repository"],
        "imageTag": asset_id,
        "assumeRoleArn": publisher,
    }
    got_destination = {k: destination.get(k) for k in want}
    assert got_destination == want, f"image asset destination is {destination!r}, expected {want!r}"

    # 2. an image is already in the repository under that tag
    pushed = _push_minimal_image(ctx, names["repository"], asset_id)["imageId"]["imageDigest"]
    (before,) = ecr.describe_images(
        repositoryName=names["repository"], imageIds=[{"imageTag": asset_id}]
    )["imageDetails"]

    # 3. the deploy finds the tag and publishes nothing; it runs as the exec role
    _cdk(
        ctx,
        work,
        ["deploy", app_stack, "--require-approval", "never", "--toolkit-stack-name", toolkit_stack],
        context,
    )
    deployed = _stack(ctx, app_stack)
    got = (deployed["StackStatus"], deployed.get("RoleARN"))
    assert got == ("CREATE_COMPLETE", exec_arn), (
        f"app stack (status, RoleARN) is {got!r}, expected ('CREATE_COMPLETE', {exec_arn!r})"
    )
    types = [
        (r["LogicalResourceId"], r["ResourceType"], r["ResourceStatus"])
        for r in cfn.describe_stack_resources(StackName=app_stack)["StackResources"]
    ]
    assert types == [("Handle", "AWS::CloudFormation::WaitConditionHandle", "CREATE_COMPLETE")], (
        f"app stack resources are {types!r}, expected the one WaitConditionHandle"
    )

    # 4. ECR holds exactly the image pushed under the asset tag, as it was before the deploy
    images = ecr.describe_images(repositoryName=names["repository"])["imageDetails"]
    got_images = [
        (i["imageDigest"], sorted(i.get("imageTags", [])), i["imagePushedAt"]) for i in images
    ]
    want_images = [(pushed, [asset_id], before["imagePushedAt"])]
    assert got_images == want_images, (
        f"repository images are {got_images!r}, expected {want_images!r}"
    )
    fetched = ecr.batch_get_image(
        repositoryName=names["repository"], imageIds=[{"imageTag": asset_id}]
    )
    got = [(i["imageId"]["imageDigest"], i["imageId"]["imageTag"]) for i in fetched["images"]]
    assert got == [(pushed, asset_id)], f"BatchGetImage by tag returned {got!r}"

    # 5. the toolkit the deploy used is as the template declares
    _assert_toolkit(ctx, toolkit_stack, qualifier, template, status="CREATE_COMPLETE")
    _assert_bootstrap_roles(ctx, qualifier)


def _image_destination(ctx, work: Path, stack_name: str) -> tuple[str, dict[str, str]]:
    """The stack's one Docker image asset id and its one destination, placeholders filled in."""
    manifest = json.loads((work / "cdk.out" / f"{stack_name}.assets.json").read_text())
    images = manifest.get("dockerImages", {})
    assert len(images) == 1, f"assets manifest lists {len(images)} image assets: {images!r}"
    asset_id, asset = next(iter(images.items()))
    destinations = list(asset["destinations"].values())
    assert len(destinations) == 1, f"the image asset has destinations {destinations!r}"
    return asset_id, {k: _resolve(ctx, v) for k, v in destinations[0].items() if isinstance(v, str)}


def _upload_blob(ecr, repository: str, blob: bytes) -> tuple[str, int]:
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    available = ecr.batch_check_layer_availability(repositoryName=repository, layerDigests=[digest])
    if available["layers"] and available["layers"][0]["layerAvailability"] == "AVAILABLE":
        return digest, available["layers"][0]["layerSize"]
    upload_id = ecr.initiate_layer_upload(repositoryName=repository)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(repositoryName=repository, uploadId=upload_id, layerDigests=[digest])
    return digest, len(blob)


def _push_minimal_image(ctx, repository: str, tag: str, config_extra: dict | None = None):
    """Push a one-empty-layer image through the ECR API and return PutImage's image."""
    ecr = ctx.client("ecr")
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w"):
        pass
    tar_bytes = tar_buffer.getvalue()
    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    layer_digest, layer_size = _upload_blob(ecr, repository, gz_buffer.getvalue())
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {
            "type": "layers",
            "diff_ids": ["sha256:" + hashlib.sha256(tar_bytes).hexdigest()],
        },
        "history": [{"created": "2024-01-01T00:00:00Z"}],
        **(config_extra or {}),
    }
    config_digest, config_size = _upload_blob(ecr, repository, json.dumps(config).encode())
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    return ecr.put_image(
        repositoryName=repository, imageManifest=json.dumps(manifest), imageTag=tag
    )["image"]


def _toolkit_names(ctx, qualifier: str) -> dict[str, str]:
    """The names the bootstrap template gives one qualifier's resources in this environment."""
    account, region = ctx.account, ctx.region
    names = {
        "bucket": f"cdk-{qualifier}-assets-{account}-{region}",
        "repository": f"cdk-{qualifier}-container-assets-{account}-{region}",
        "version_parameter": f"/cdk-bootstrap/{qualifier}/version",
    }
    for role in _ROLES:
        names[role] = f"cdk-{qualifier}-{role}-{account}-{region}"
    return names


def _bootstrap(ctx, toolkit_stack: str, flags: list[str], *, env_extra=None) -> str:
    """`cdk bootstrap` into this run's environment with *flags*; returns the CLI's output."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    env = ctx.subprocess_env()
    env.update(env_extra or {})
    command = [
        "cdk",
        "bootstrap",
        f"aws://{ctx.account}/{ctx.region}",
        "--toolkit-stack-name",
        toolkit_stack,
        *flags,
        "--tags",
        f"sim2real={CHECK}",
        "--ci",
        "--no-version-reporting",
        "--no-notices",
        "--no-color",
    ]
    result = subprocess.run(
        command,
        cwd=scratch,
        env=env,
        capture_output=True,
        text=True,
        timeout=_step_timeout(ctx, _BOOTSTRAP_TIMEOUT_S),
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"`cdk bootstrap {' '.join(flags)}` exited {result.returncode}, expected 0; output tail: "
        f"{output[-1200:]!r}"
    )
    return output


def _bootstrap_template(ctx) -> dict[str, Any]:
    """The bootstrap template the installed CLI deploys, read offline."""
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkbootshow-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    result = subprocess.run(
        ["cdk", "bootstrap", "--show-template", "--json", "--ci"],
        cwd=scratch,
        env=ctx.subprocess_env(),
        capture_output=True,
        text=True,
        timeout=_step_timeout(ctx, _SHOW_TEMPLATE_TIMEOUT_S),
    )
    assert result.returncode == 0, (
        f"`cdk bootstrap --show-template` exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1000:]!r}"
    )
    # The CLI may write a notice line before the JSON object.
    return json.loads(result.stdout[result.stdout.index("{") :])


def _stage_app(ctx, files: dict[str, str]) -> Path:
    """Write a CDK app into a temp dir so `cdk.out` never lands in the repo."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkapp-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    for relative, text in files.items():
        path = work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return work


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, env_extra=None) -> str:
    """Run the CDK CLI on the app in *work*, require exit 0, and return its output."""
    ctx.verify_account_safety()
    # The app runs under this interpreter, which has aws-cdk-lib.
    command = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    command += ["--app", f"{sys.executable} app.py"]
    for key, value in context.items():
        command += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env.update(env_extra or {})
    result = subprocess.run(
        command,
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=_step_timeout(ctx, _DEPLOY_TIMEOUT_S),
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, (
        f"`cdk {' '.join(args)}` exited {result.returncode}, expected 0; output tail: "
        f"{output[-1200:]!r}"
    )
    return output


def _stack(ctx, name: str) -> dict[str, Any]:
    return ctx.client("cloudformation").describe_stacks(StackName=name)["Stacks"][0]


def _outputs(stack: dict[str, Any]) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else [value]


def _statements(document: Any) -> list[dict[str, Any]]:
    """A policy's statements in order, with Action, Resource and principal values as sorted lists.

    IAM keeps either JSON form of a one-element value, so this makes both compare exactly.
    """
    if isinstance(document, str):
        document = json.loads(document)
    out = []
    for statement in _as_list(document["Statement"]):
        normal: dict[str, Any] = {"Effect": statement["Effect"]}
        for key in ("Sid", "Condition"):
            if key in statement:
                normal[key] = statement[key]
        for key in ("Action", "Resource"):
            if key in statement:
                normal[key] = sorted(_as_list(statement[key]))
        if "Principal" in statement:
            principal = statement["Principal"]
            normal["Principal"] = (
                principal
                if isinstance(principal, str)
                else {k: sorted(_as_list(v)) for k, v in principal.items()}
            )
        out.append(normal)
    return out


def _expected_trust(
    ctx, role: str, *, trusted=(), trusted_for_lookup=(), deny_external_id=True
) -> list[dict[str, Any]]:
    """The trust statements the bootstrap template gives *role*, in template order."""
    if role == "cfn-exec-role":
        return [
            {
                "Effect": "Allow",
                "Action": ["sts:AssumeRole"],
                "Principal": {"Service": ["cloudformation.amazonaws.com"]},
            }
        ]

    def pair(accounts) -> list[dict[str, Any]]:
        principal = {"AWS": sorted(f"arn:aws:iam::{a}:root" for a in accounts)}
        assume: dict[str, Any] = {"Effect": "Allow", "Action": ["sts:AssumeRole"]}
        if deny_external_id:
            assume["Condition"] = {"Null": {"sts:ExternalId": "true"}}
        assume["Principal"] = principal
        return [assume, {"Effect": "Allow", "Action": ["sts:TagSession"], "Principal": principal}]

    statements = pair([ctx.account])
    if role == "lookup-role" and trusted_for_lookup:
        statements += pair(trusted_for_lookup)
    if trusted:
        statements += pair(trusted)
    return statements


def _assert_bootstrap_roles(
    ctx,
    qualifier: str,
    *,
    exec_policies=(_ADMIN,),
    boundary_arn=None,
    trusted=(),
    trusted_for_lookup=(),
    deny_external_id=True,
) -> dict[str, dict[str, Any]]:
    """IAM's view of the five bootstrap roles: ARN, trust, boundary and policies; returns them."""
    iam = ctx.client("iam")
    names = _toolkit_names(ctx, qualifier)
    account, region = ctx.account, ctx.region
    managed = {
        "cfn-exec-role": sorted(exec_policies),
        "deploy-role": ["arn:aws:iam::aws:policy/AWSCloudFormationReadOnlyAccess"],
        "file-publishing-role": [],
        "image-publishing-role": [],
        "lookup-role": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
    }
    inline = {
        "cfn-exec-role": [],
        "deploy-role": ["default"],
        "file-publishing-role": [
            f"cdk-{qualifier}-file-publishing-role-default-policy-{account}-{region}"
        ],
        "image-publishing-role": [
            f"cdk-{qualifier}-image-publishing-role-default-policy-{account}-{region}"
        ],
        "lookup-role": ["LookupRolePolicy"],
    }
    roles = {}
    for role in _ROLES:
        name = names[role]
        got = iam.get_role(RoleName=name)["Role"]
        assert got["Arn"] == f"arn:aws:iam::{account}:role/{name}", (
            f"{role} ARN is {got['Arn']!r}, expected arn:aws:iam::{account}:role/{name}"
        )
        trust = _statements(got["AssumeRolePolicyDocument"])
        want = _expected_trust(
            ctx,
            role,
            trusted=trusted,
            trusted_for_lookup=trusted_for_lookup,
            deny_external_id=deny_external_id,
        )
        assert trust == want, f"{role} trust statements are {trust!r}, expected {want!r}"
        bounded = boundary_arn is not None and role == "cfn-exec-role"
        want_boundary = (
            {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": boundary_arn}
            if bounded
            else None
        )
        assert got.get("PermissionsBoundary") == want_boundary, (
            f"{role} permissions boundary is {got.get('PermissionsBoundary')!r}, expected "
            f"{want_boundary!r}"
        )
        attached = sorted(
            p["PolicyArn"]
            for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
        )
        assert attached == managed[role], (
            f"{role} managed policies are {attached!r}, expected {managed[role]!r}"
        )
        policies = sorted(iam.list_role_policies(RoleName=name)["PolicyNames"])
        assert policies == inline[role], (
            f"{role} inline policies are {policies!r}, expected {inline[role]!r}"
        )
        roles[role] = got
    return roles


def _assert_toolkit(
    ctx, toolkit_stack: str, qualifier: str, template: dict[str, Any], *, status: str
) -> dict[str, Any]:
    """CloudFormation, SSM, S3, ECR and IAM views of one modern toolkit stack; returns the stack."""
    names = _toolkit_names(ctx, qualifier)
    version = template["Resources"]["CdkBootstrapVersion"]["Properties"]["Value"]
    stack = _stack(ctx, toolkit_stack)
    assert stack["StackStatus"] == status, (
        f"toolkit stack is {stack['StackStatus']!r}, expected {status!r}"
    )
    outputs = _outputs(stack)
    _assert_bucket_domain(ctx, outputs.pop("BucketDomainName", ""), names["bucket"])
    want_outputs = {
        "BucketName": names["bucket"],
        "FileAssetKeyArn": "AWS_MANAGED_KEY",
        "ImageRepositoryName": names["repository"],
        "BootstrapVersion": version,
    }
    assert outputs == want_outputs, f"toolkit outputs are {outputs!r}, expected {want_outputs!r}"
    parameter = _version_parameter(ctx, names["version_parameter"])
    assert (parameter["Type"], parameter["Value"]) == ("String", version), (
        f"{names['version_parameter']!r} is {parameter['Type']!r} {parameter['Value']!r}, "
        f"expected 'String' {version!r}"
    )
    _assert_staging_bucket(ctx, names["bucket"], template)
    repos = ctx.client("ecr").describe_repositories(repositoryNames=[names["repository"]])
    got = [(r["repositoryName"], r["imageTagMutability"]) for r in repos["repositories"]]
    assert got == [(names["repository"], "IMMUTABLE")], (
        f"describe_repositories({names['repository']!r}) returned {got!r}"
    )
    _assert_role_policies(ctx, template, stack)
    return stack


def _assert_staging_bucket(ctx, bucket: str, template: dict[str, Any] | None) -> None:
    """S3's view of a staging bucket: versioning, lifecycle, public access block, KMS, TLS policy.

    *template* is the modern template that built the bucket; None is the legacy template, which
    neither versions the bucket nor gives it lifecycle rules.
    """
    s3 = ctx.client("s3")
    versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    want_versioning = "Enabled" if template else None
    assert versioning == want_versioning, (
        f"bucket {bucket} versioning is {versioning!r}, expected {want_versioning!r}"
    )
    if template:
        _assert_lifecycle(ctx, bucket, template)
    block = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert block == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }, f"bucket {bucket} public access block is {block!r}, expected all four True"
    rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    # The template's settings only: S3 adds its own, such as the encryption types it blocks.
    keys = ("ApplyServerSideEncryptionByDefault", "BucketKeyEnabled")
    defaults = [{k: r.get(k) for k in keys} for r in rules]
    assert defaults == _KMS_DEFAULT_RULES, (
        f"bucket {bucket} encryption rules are {rules!r}, expected {_KMS_DEFAULT_RULES!r}"
    )
    arn = f"arn:aws:s3:::{bucket}"
    statements = _statements(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    assert statements == [
        {
            "Effect": "Deny",
            "Sid": "AllowSSLRequestsOnly",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            "Action": ["s3:*"],
            "Resource": sorted([arn, f"{arn}/*"]),
            "Principal": "*",
        }
    ], f"bucket {bucket} policy statements are {statements!r}"


def _stack_missing(exc: ClientError, stack: str) -> bool:
    error = exc.response["Error"]
    return (error["Code"], error.get("Message")) in (
        ("ValidationError", f"Stack with id {stack} does not exist"),
        ("ValidationError", f"Stack [{stack}] does not exist"),
    )


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    except ClientError as exc:
        if _stack_missing(exc, stack):
            return
        raise
    stack_id = described["StackId"]
    if described.get("EnableTerminationProtection"):
        cfn.update_termination_protection(StackName=stack_id, EnableTerminationProtection=False)
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge every version and delete marker, then the bucket. Only this run's own buckets."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _empty_repository(ctx, repository: str) -> None:
    """Delete every image in this run's container-assets repository, so its stack can delete it."""
    ecr = ctx.client("ecr")
    try:
        ids = [
            image
            for page in ecr.get_paginator("list_images").paginate(repositoryName=repository)
            for image in page.get("imageIds", [])
        ]
        for start in range(0, len(ids), 100):
            ecr.batch_delete_image(repositoryName=repository, imageIds=ids[start : start + 100])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _delete_policy(ctx, arn: str) -> None:
    try:
        ctx.client("iam").delete_policy(PolicyArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _teardown(
    ctx,
    toolkit_stack: str,
    qualifier: str,
    *,
    app_stacks=(),
    buckets=(),
    policies=(),
) -> None:
    """Delete the app stacks and their functions' log groups, then the toolkit and what it keeps.

    Raises on any leftover.
    """
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S

    def left() -> float:
        return max(30.0, deadline - time.monotonic())

    names = _toolkit_names(ctx, qualifier)
    log_groups: list[str] = []
    for app_stack in app_stacks:
        log_groups += _function_log_groups(ctx, app_stack)
        try:
            _delete_stack_and_wait(ctx, app_stack, timeout_s=left())
        except Exception as exc:  # noqa: BLE001 - raised below with what it keeps
            # The app stack deletes as the toolkit's exec role: deleting the toolkit now strands it.
            raise AssertionError(
                f"app stack {app_stack} not deleted; toolkit stack {toolkit_stack} kept: {exc!r}"
            ) from exc
    problems: list[str] = []
    all_buckets = [names["bucket"], *[b for b in buckets if b != names["bucket"]]]
    steps: list[tuple[str, Any]] = [
        *[
            (f"log group {g}", lambda g=g: _reap_log_group(ctx, g, budget_s=min(120.0, left())))
            for g in log_groups
        ],
        (f"repository {names['repository']}", lambda: _empty_repository(ctx, names["repository"])),
        (
            f"toolkit stack {toolkit_stack}",
            lambda: _delete_stack_and_wait(ctx, toolkit_stack, timeout_s=left()),
        ),
        # The stack retains its staging bucket; its delete removes the bucket policy first.
        *[(f"bucket {b}", lambda b=b: _empty_and_delete_bucket(ctx, b)) for b in all_buckets],
        # A boundary policy is deleted only once no role uses it.
        *[(f"policy {p}", lambda p=p: _delete_policy(ctx, p)) for p in policies],
    ]
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - collected and raised below
            problems.append(f"{label}: {exc!r}")
    try:
        # IAM reports a deleted role or policy for a while after its delete.
        remaining = _poll(
            lambda: _remnants(ctx, qualifier, all_buckets, policies),
            lambda r: not r,
            budget_s=min(60.0, left()),
        )
    except ClientError as exc:
        raise AssertionError(
            f"teardown left problems behind: {problems!r}; reading remnants failed: {exc!r}"
        ) from exc
    if remaining:
        problems.append(f"remnants still present: {remaining!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


def _remnants(ctx, qualifier: str, buckets, policies) -> list[str]:
    """What the scenario left behind, by exact name. Never a prefix sweep across the account."""
    names = _toolkit_names(ctx, qualifier)
    probes = [
        (
            f"ssm parameter {names['version_parameter']}",
            ("ParameterNotFound",),
            lambda: ctx.client("ssm").get_parameter(Name=names["version_parameter"]),
        ),
        (
            f"repository {names['repository']}",
            ("RepositoryNotFoundException",),
            lambda: ctx.client("ecr").describe_repositories(repositoryNames=[names["repository"]]),
        ),
        *[
            (
                f"bucket {b}",
                ("404", "NoSuchBucket"),
                lambda b=b: ctx.client("s3").head_bucket(Bucket=b),
            )
            for b in buckets
        ],
        *[
            (
                f"role {names[r]}",
                ("NoSuchEntity",),
                lambda r=r: ctx.client("iam").get_role(RoleName=names[r]),
            )
            for r in _ROLES
        ],
        *[
            (
                f"policy {p}",
                ("NoSuchEntity",),
                lambda p=p: ctx.client("iam").get_policy(PolicyArn=p),
            )
            for p in policies
        ],
    ]
    remaining: list[str] = []
    for label, absent_codes, probe in probes:
        try:
            probe()
            remaining.append(label)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in absent_codes:
                raise
    return remaining


def _resolve(ctx, value: str) -> str:
    """An asset-manifest value with the environment placeholders filled in."""
    return (
        value.replace("${AWS::AccountId}", ctx.account)
        .replace("${AWS::Region}", ctx.region)
        .replace("${AWS::Partition}", "aws")
    )


def _step_timeout(ctx, ceiling_s: float) -> float:
    """A step's timeout: *ceiling_s*, capped so the step ends before the runner stops the check."""
    left = ctx.time_left()
    return ceiling_s if left is None else max(1.0, min(ceiling_s, left - _RESERVE_S))


def _poll(read, done, *, budget_s: float, interval_s: float = 2.0):
    """Call *read* until *done* accepts its value or *budget_s* passes; returns the last value.

    IAM and SSM are eventually consistent: a read right after a write may still see the old state.
    """
    deadline = time.monotonic() + budget_s
    while True:
        value = read()
        if done(value) or time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)


def _version_parameter(ctx, name: str) -> dict[str, Any]:
    """The toolkit's version parameter; a read right after the bootstrap may not find it yet."""
    ssm = ctx.client("ssm")

    def read() -> dict[str, Any] | None:
        try:
            return ssm.get_parameter(Name=name)["Parameter"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
            return None

    parameter = _poll(read, lambda p: p is not None, budget_s=_step_timeout(ctx, 30.0))
    assert parameter is not None, f"GetParameter({name!r}) found no parameter after the bootstrap"
    return parameter


def _template_values(ctx, template: dict[str, Any], stack: dict[str, Any]):
    """A resolver of *template*'s intrinsic functions for *stack*, the stack deployed from it.

    Parameters take the stack's values and pseudo parameters this run's environment; each role,
    bucket, repository and SSM parameter resource resolves to the name its properties give it.
    """
    given = {p["ParameterKey"]: p.get("ParameterValue", "") for p in stack.get("Parameters", [])}
    refs: dict[str, Any] = {
        "AWS::AccountId": ctx.account,
        "AWS::Region": ctx.region,
        "AWS::Partition": "aws",
        "AWS::URLSuffix": "amazonaws.com",
        "AWS::NoValue": _NO_VALUE,
    }
    for key, spec in template.get("Parameters", {}).items():
        value = given.get(key, spec.get("Default", ""))
        refs[key] = value.split(",") if spec.get("Type") == "CommaDelimitedList" else value
    conditions: dict[str, bool] = {}

    def condition(name: str) -> bool:
        if name not in conditions:
            conditions[name] = bool(resolve(template["Conditions"][name]))
        return conditions[name]

    def sub(text: str, extra: dict[str, Any]) -> str:
        def one(match: re.Match) -> str:
            name = match.group(1)
            if name.startswith("!"):
                return "${" + name[1:] + "}"
            return str(extra[name] if name in extra else refs[name])

        return re.sub(r"\$\{([^}]+)\}", one, text)

    def resolve(value: Any) -> Any:
        if isinstance(value, list):
            return [v for v in (resolve(item) for item in value) if v is not _NO_VALUE]
        if not isinstance(value, dict):
            return value
        if len(value) == 1:
            ((key, arg),) = value.items()
            if key == "Ref":
                return refs[arg]
            if key == "Condition":
                return condition(arg)
            if key == "Fn::If":
                return resolve(arg[1] if condition(arg[0]) else arg[2])
            if key == "Fn::Equals":
                first, second = resolve(arg)
                return first == second
            if key == "Fn::Not":
                return not resolve(arg[0])
            if key == "Fn::And":
                return all(resolve(a) for a in arg)
            if key == "Fn::Or":
                return any(resolve(a) for a in arg)
            if key == "Fn::Join":
                return arg[0].join(resolve(arg[1]))
            if key == "Fn::Sub":
                if isinstance(arg, str):
                    return sub(arg, {})
                return sub(arg[0], {k: resolve(v) for k, v in arg[1].items()})
            if key == "Fn::GetAtt":
                return refs[".".join(arg) if isinstance(arg, list) else arg]
            assert not key.startswith("Fn::"), f"no resolver for {key} in the bootstrap template"
        out = {k: resolve(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v is not _NO_VALUE}

    name_of = {
        "AWS::IAM::Role": ("RoleName", f"arn:aws:iam::{ctx.account}:role/{{}}"),
        "AWS::S3::Bucket": ("BucketName", "arn:aws:s3:::{}"),
        "AWS::ECR::Repository": (
            "RepositoryName",
            f"arn:aws:ecr:{ctx.region}:{ctx.account}:repository/{{}}",
        ),
        "AWS::SSM::Parameter": ("Name", None),
    }
    for logical_id, resource in template["Resources"].items():
        if resource["Type"] not in name_of:
            continue
        if "Condition" in resource and not condition(resource["Condition"]):
            continue
        prop, arn = name_of[resource["Type"]]
        refs[logical_id] = resolve(resource["Properties"][prop])
        if arn:
            refs[f"{logical_id}.Arn"] = arn.format(refs[logical_id])
    return resolve


def _policy_statements(document: Any) -> list[dict[str, Any]]:
    """A policy's statements in order, with every multi-valued element as a sorted list.

    IAM keeps either JSON form of a one-element value, so this makes both compare exactly.
    """
    if isinstance(document, str):
        document = json.loads(document)

    def listed(value: Any) -> list[Any]:
        return sorted(value) if isinstance(value, list) else [value]

    statements = document["Statement"]
    out = []
    for statement in statements if isinstance(statements, list) else [statements]:
        normal: dict[str, Any] = {"Effect": statement["Effect"]}
        if "Sid" in statement:
            normal["Sid"] = statement["Sid"]
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in statement:
                normal[key] = listed(statement[key])
        principal = statement.get("Principal")
        if principal is not None:
            normal["Principal"] = (
                principal
                if isinstance(principal, str)
                else {k: listed(v) for k, v in principal.items()}
            )
        if "Condition" in statement:
            normal["Condition"] = {
                op: {k: listed(v) for k, v in keys.items()}
                for op, keys in statement["Condition"].items()
            }
        out.append(normal)
    return out


def _assert_role_policies(ctx, template: dict[str, Any], stack: dict[str, Any]) -> None:
    """IAM's inline policies of each role in *template*, names and documents, as it declares them.

    A role's own `Policies` and each `AWS::IAM::Policy` naming the role both land inline on it.
    """
    iam = ctx.client("iam")
    resolve = _template_values(ctx, template, stack)
    want: dict[str, dict[str, Any]] = {}
    for resource in template["Resources"].values():
        if "Condition" in resource and not resolve({"Condition": resource["Condition"]}):
            continue
        props = resource.get("Properties", {})
        if resource["Type"] == "AWS::IAM::Role":
            role = want.setdefault(resolve(props["RoleName"]), {})
            for policy in resolve(props.get("Policies", [])):
                role[policy["PolicyName"]] = policy["PolicyDocument"]
        elif resource["Type"] == "AWS::IAM::Policy":
            for name in resolve(props["Roles"]):
                document = resolve(props["PolicyDocument"])
                want.setdefault(name, {})[resolve(props["PolicyName"])] = document
    for role, policies in sorted(want.items()):
        names = sorted(iam.list_role_policies(RoleName=role)["PolicyNames"])
        assert names == sorted(policies), (
            f"{role} inline policies are {names!r}, expected the template's {sorted(policies)!r}"
        )
        for name, document in sorted(policies.items()):
            stored = iam.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"]
            got, expected = _policy_statements(stored), _policy_statements(document)
            diff = [
                (i, g, e) for i, (g, e) in enumerate(zip(got, expected, strict=False)) if g != e
            ][:1]
            assert got == expected, (
                f"{role} inline policy {name} has {len(got)} statements, the template "
                f"{len(expected)}; first difference (index, IAM, template): {diff!r}"
            )


def _assert_lifecycle(ctx, bucket: str, template: dict[str, Any]) -> None:
    """S3's lifecycle rules of the staging bucket against the template's, by id and setting."""
    lifecycle = ctx.client("s3").get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    want_rules = template["Resources"]["StagingBucket"]["Properties"]["LifecycleConfiguration"]
    got = sorted(
        (
            r["ID"],
            r["Status"],
            r.get("NoncurrentVersionExpiration", {}).get("NoncurrentDays"),
            r.get("AbortIncompleteMultipartUpload", {}).get("DaysAfterInitiation"),
        )
        for r in lifecycle
    )
    want = sorted(
        (
            r["Id"],
            r["Status"],
            r.get("NoncurrentVersionExpiration", {}).get("NoncurrentDays"),
            r.get("AbortIncompleteMultipartUpload", {}).get("DaysAfterInitiation"),
        )
        for r in want_rules["Rules"]
    )
    assert got == want, f"bucket {bucket} lifecycle rules are {lifecycle!r}, expected {want!r}"


def _function_log_groups(ctx, stack: str) -> list[str]:
    """The `/aws/lambda/<name>` log group of each function in *stack*, which the stack never owns.

    Lambda creates the group on the function's first log line; deleting the stack leaves it.
    """
    try:
        resources = ctx.client("cloudformation").describe_stack_resources(StackName=stack)
    except ClientError as exc:
        if _stack_missing(exc, stack):
            return []
        raise
    return [
        f"/aws/lambda/{r['PhysicalResourceId']}"
        for r in resources["StackResources"]
        if r["ResourceType"] == "AWS::Lambda::Function" and r.get("PhysicalResourceId")
    ]


def _reap_log_group(ctx, name: str, *, budget_s: float) -> None:
    """Delete log group *name* until three consecutive reads find it absent."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < 3:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < 3:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name!r} still present after {budget_s}s")
            time.sleep(_POLL_S)


def _assert_bucket_domain(ctx, domain: str, bucket: str) -> None:
    """The BucketDomainName output names the bucket's regional S3 host, by its labels."""
    labels = f"{bucket}.s3.{ctx.region}."
    assert domain.startswith(labels), (
        f"toolkit output BucketDomainName is {domain!r}, expected the host {labels}<domain>"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
