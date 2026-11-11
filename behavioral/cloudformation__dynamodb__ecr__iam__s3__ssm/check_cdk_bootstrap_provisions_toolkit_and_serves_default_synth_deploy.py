"""cdk-bootstrap-provisions-toolkit-and-serves-default-synth-deploy."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-bootstrap-provisions-toolkit-and-serves-default-synth-deploy"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "ecr", "iam", "s3", "ssm"]

_BOOTSTRAP_TIMEOUT_S = 600.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_table_bootstrap"
# The five roles the bootstrap template names `cdk-<qualifier>-<role>-<account>-<region>`.
_ROLES = (
    "cfn-exec-role",
    "deploy-role",
    "file-publishing-role",
    "image-publishing-role",
    "lookup-role",
)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk bootstrap` builds the toolkit resources its template declares.

    A DefaultStackSynthesizer deploy then runs as the cfn-exec role, resolves the version from SSM
    and publishes its template to the staging bucket.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.account
    region = ctx.region
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    ecr = ctx.client("ecr")
    ddb = ctx.client("dynamodb")

    # A per-run qualifier makes every bootstrap resource unique to this run.
    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    app_stack = ctx.unique_name("sim2real-cdkbootok-")
    staging_bucket = f"cdk-{qualifier}-assets-{account}-{region}"
    repository = f"cdk-{qualifier}-container-assets-{account}-{region}"
    version_parameter = f"/cdk-bootstrap/{qualifier}/version"
    role_arn = {
        r: f"arn:aws:iam::{account}:role/cdk-{qualifier}-{r}-{account}-{region}" for r in _ROLES
    }

    work = _stage_app(ctx, _APP)
    context = {
        "account": account,
        "region": region,
        "stack_name": app_stack,
        "synth": "default",
        "qualifier": qualifier,
    }
    template_version = _bootstrap_template_version(ctx)

    # 1. bootstrap. Registered first, so a bootstrap that fails part-way is still torn down; the
    # teardown deletes the app stack first, then everything bootstrap made.
    ctx.on_cleanup(
        lambda: _teardown_with_bootstrap(
            ctx, app_stack, toolkit_stack, staging_bucket, repository, qualifier, version_parameter
        )
    )
    _bootstrap(ctx, account, qualifier, toolkit_stack)

    # 2. the toolkit stack, its outputs and its export
    toolkit = cfn.describe_stacks(StackName=toolkit_stack)["Stacks"][0]
    assert toolkit["StackStatus"] == "CREATE_COMPLETE", (
        f"toolkit stack is {toolkit['StackStatus']!r}, expected 'CREATE_COMPLETE'"
    )
    assert {"Key": "sim2real", "Value": CHECK} in toolkit.get("Tags", []), (
        f"toolkit stack tags {toolkit.get('Tags')!r} lack the --tags value sim2real={CHECK}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in toolkit.get("Outputs", [])}
    domain = outputs.pop("BucketDomainName", "")
    assert domain.startswith(f"{staging_bucket}."), (
        f"toolkit BucketDomainName {domain!r} does not name the staging bucket {staging_bucket!r}"
    )
    assert outputs == {
        "BucketName": staging_bucket,
        "FileAssetKeyArn": "AWS_MANAGED_KEY",
        "ImageRepositoryName": repository,
        "BootstrapVersion": template_version,
    }, f"toolkit stack outputs were {outputs!r}"
    exports = {
        e["Name"]: (e["Value"], e["ExportingStackId"])
        for page in cfn.get_paginator("list_exports").paginate()
        for e in page.get("Exports", [])
    }
    export_name = f"CdkBootstrap-{qualifier}-FileAssetKeyArn"
    assert exports.get(export_name) == ("AWS_MANAGED_KEY", toolkit["StackId"]), (
        f"export {export_name!r} is {exports.get(export_name)!r}, expected "
        f"('AWS_MANAGED_KEY', {toolkit['StackId']!r})"
    )

    # 3. the version parameter the CLI and every app template read
    parameter = ssm.get_parameter(Name=version_parameter)["Parameter"]
    assert (parameter["Type"], parameter["Value"]) == ("String", template_version), (
        f"{version_parameter!r} is {parameter['Type']!r} {parameter['Value']!r}, expected "
        f"'String' {template_version!r}"
    )

    # 4. the staging bucket's configuration
    versioning = s3.get_bucket_versioning(Bucket=staging_bucket).get("Status")
    assert versioning == "Enabled", (
        f"staging bucket versioning is {versioning!r}, expected 'Enabled'"
    )
    block = s3.get_public_access_block(Bucket=staging_bucket)["PublicAccessBlockConfiguration"]
    assert block == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }, f"staging bucket public access block is {block!r}, expected all four True"
    rules = s3.get_bucket_encryption(Bucket=staging_bucket)["ServerSideEncryptionConfiguration"][
        "Rules"
    ]
    defaults = [r["ApplyServerSideEncryptionByDefault"] for r in rules]
    assert defaults == [{"SSEAlgorithm": "aws:kms"}], (
        f"staging bucket encryption rules are {rules!r}, expected one aws:kms default with no "
        f"KMSMasterKeyID"
    )
    statements = json.loads(s3.get_bucket_policy(Bucket=staging_bucket)["Policy"])["Statement"]
    bucket_arn = f"arn:aws:s3:::{staging_bucket}"
    got = [
        (
            s.get("Sid"),
            s.get("Effect"),
            s.get("Principal"),
            s.get("Action"),
            sorted(s.get("Resource", [])),
            s.get("Condition"),
        )
        for s in statements
    ]
    assert got == [
        (
            "AllowSSLRequestsOnly",
            "Deny",
            "*",
            "s3:*",
            [bucket_arn, f"{bucket_arn}/*"],
            {"Bool": {"aws:SecureTransport": "false"}},
        )
    ], f"staging bucket policy statements are {statements!r}"

    # 5. the container-asset repository
    repos = ecr.describe_repositories(repositoryNames=[repository])["repositories"]
    assert [(r["repositoryName"], r["imageTagMutability"]) for r in repos] == [
        (repository, "IMMUTABLE")
    ], f"describe_repositories({repository!r}) returned {repos!r}"

    # 6. exactly five bootstrap roles; the exec role is trusted by CloudFormation alone
    roles = sorted(
        r["RoleName"]
        for page in iam.get_paginator("list_roles").paginate()
        for r in page["Roles"]
        if r["RoleName"].startswith(f"cdk-{qualifier}-")
    )
    assert roles == sorted(a.rpartition("/")[2] for a in role_arn.values()), (
        f"bootstrap roles for qualifier {qualifier!r} are {roles!r}, expected the five "
        f"{sorted(_ROLES)!r}"
    )
    exec_role = iam.get_role(RoleName=role_arn["cfn-exec-role"].rpartition("/")[2])["Role"]
    assert exec_role["Arn"] == role_arn["cfn-exec-role"], (
        f"cfn-exec role ARN is {exec_role['Arn']!r}, expected {role_arn['cfn-exec-role']!r}"
    )
    exec_trust = [
        (s.get("Effect"), s.get("Principal"), s.get("Action"))
        for s in exec_role["AssumeRolePolicyDocument"]["Statement"]
    ]
    assert exec_trust == [
        ("Allow", {"Service": "cloudformation.amazonaws.com"}, "sts:AssumeRole")
    ], f"cfn-exec role trust is {exec_trust!r}, expected only CloudFormation to assume it"
    exec_policies = [
        p["PolicyArn"]
        for p in iam.list_attached_role_policies(RoleName=exec_role["RoleName"])["AttachedPolicies"]
    ]
    assert exec_policies == ["arn:aws:iam::aws:policy/AdministratorAccess"], (
        f"cfn-exec role managed policies are {exec_policies!r}, expected AdministratorAccess "
        f"alone (no --cloudformation-execution-policies was given)"
    )
    deploy_policies = [
        p["PolicyArn"]
        for p in iam.list_attached_role_policies(
            RoleName=role_arn["deploy-role"].rpartition("/")[2]
        )["AttachedPolicies"]
    ]
    assert deploy_policies == ["arn:aws:iam::aws:policy/AWSCloudFormationReadOnlyAccess"], (
        f"deploy role managed policies are {deploy_policies!r}, expected "
        f"AWSCloudFormationReadOnlyAccess alone"
    )

    # 7. a DefaultStackSynthesizer deploy runs through that environment
    _cdk(
        ctx,
        work,
        ["deploy", app_stack, "--require-approval", "never"],
        context,
        timeout_s=_DEPLOY_TIMEOUT_S,
        expect_rc=0,
    )
    deployed = cfn.describe_stacks(StackName=app_stack)["Stacks"][0]
    assert deployed["StackStatus"] == "CREATE_COMPLETE", (
        f"app stack is {deployed['StackStatus']!r}, expected 'CREATE_COMPLETE'"
    )
    assert deployed.get("RoleARN") == role_arn["cfn-exec-role"], (
        f"app stack RoleARN is {deployed.get('RoleARN')!r}, expected the bootstrap cfn-exec "
        f"role {role_arn['cfn-exec-role']!r}"
    )
    bootstrap_param = {p["ParameterKey"]: p for p in deployed.get("Parameters", [])}.get(
        "BootstrapVersion", {}
    )
    assert (bootstrap_param.get("ParameterValue"), bootstrap_param.get("ResolvedValue")) == (
        version_parameter,
        template_version,
    ), (
        f"app stack parameter BootstrapVersion is {bootstrap_param!r}, expected "
        f"ParameterValue {version_parameter!r} resolved from SSM to {template_version!r}"
    )

    # 8. the template went through the staging bucket, encrypted by its default
    manifest = json.loads((work / "cdk.out" / f"{app_stack}.assets.json").read_text())
    template_assets = [
        a
        for a in manifest["files"].values()
        if a["source"].get("path") == f"{app_stack}.template.json"
    ]
    assert len(template_assets) == 1, (
        f"assets manifest lists {len(template_assets)} template assets for {app_stack!r}"
    )
    destinations = list(template_assets[0]["destinations"].values())
    assert len(destinations) == 1, f"the template asset has destinations {destinations!r}"
    destination = destinations[0]
    assert destination["bucketName"] == staging_bucket, (
        f"template asset destination bucket is {destination['bucketName']!r}, expected "
        f"{staging_bucket!r}"
    )
    assert (
        destination["assumeRoleArn"].replace("${AWS::Partition}", "aws")
        == (role_arn["file-publishing-role"])
    ), f"template asset publishing role is {destination['assumeRoleArn']!r}"
    key = destination["objectKey"]
    published = s3.get_object(Bucket=staging_bucket, Key=key)
    local = (work / "cdk.out" / f"{app_stack}.template.json").read_bytes()
    assert published["Body"].read() == local, (
        f"s3://{staging_bucket}/{key} does not hold the synthesized template's bytes"
    )
    assert published.get("ServerSideEncryption") == "aws:kms", (
        f"the published template is encrypted with "
        f"{published.get('ServerSideEncryption')!r}, expected the bucket default 'aws:kms'"
    )

    # 9. the deployed table takes a write and returns it
    table = {o["OutputKey"]: o["OutputValue"] for o in deployed.get("Outputs", [])}["TableName"]
    item_key, marker = ctx.unique_name("key-"), ctx.unique_name("marker-")
    ddb.put_item(TableName=table, Item={"pk": {"S": item_key}, "marker": {"S": marker}})
    item = ddb.get_item(TableName=table, Key={"pk": {"S": item_key}}, ConsistentRead=True).get(
        "Item"
    )
    assert item == {"pk": {"S": item_key}, "marker": {"S": marker}}, (
        f"GetItem on the deployed table {table!r} returned {item!r}, expected the item just put"
    )


def _bootstrap(ctx, account: str, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier in a scratch cwd.

    `--bootstrap-kms-key-id AWS_MANAGED_KEY`: an empty value makes the template mint a customer
    key with a 7-day deletion window.
    """
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk",
        "bootstrap",
        f"aws://{account}/{ctx.region}",
        "--qualifier",
        qualifier,
        "--toolkit-stack-name",
        toolkit_stack,
        "--bootstrap-kms-key-id",
        "AWS_MANAGED_KEY",
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
        env=ctx.subprocess_env(),
        capture_output=True,
        text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S,
    )
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0; "
        f"output tail: {(result.stdout + result.stderr)[-1200:]!r}"
    )


def _bootstrap_template_version(ctx) -> str:
    """The SSM version value the installed CLI's bootstrap template declares, read offline."""
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkbootshow-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    result = subprocess.run(
        ["cdk", "bootstrap", "--show-template", "--json", "--ci"],
        cwd=scratch,
        env=ctx.subprocess_env(),
        capture_output=True,
        text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S,
    )
    assert result.returncode == 0, (
        f"`cdk bootstrap --show-template` exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1000:]!r}"
    )
    # The CLI may write a notice line before the JSON object.
    template = json.loads(result.stdout[result.stdout.index("{") :])
    return template["Resources"]["CdkBootstrapVersion"]["Properties"]["Value"]


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app this check references is missing or incomplete at {source} (artifact defect)"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(
        source,
        staged,
        ignore=shutil.ignore_patterns("cdk.out", "out-*", ".venv", "__pycache__", "node_modules"),
    )
    return staged


def _cdk(
    ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float, expect_rc: int
) -> None:
    """Run the CDK CLI in *work* and require exit code *expect_rc*."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    if args[0] in ("deploy", "destroy", "synth"):
        # The app runs under this interpreter, which has aws-cdk-lib, not cdk.json's bare python3.
        cmd += ["--app", f"{sys.executable} app.py"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(
        cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True, text=True, timeout=timeout_s
    )
    output = result.stdout + result.stderr
    assert result.returncode == expect_rc, (
        f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output tail: "
        f"{output[-1200:]!r}"
    )


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] in (f"Stack with id {stack} does not exist", f"Stack [{stack}] does not exist"):
            return
        raise
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
    """Purge every version and delete marker, then the bucket. Only this run's staging bucket."""
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


def _teardown_with_bootstrap(
    ctx,
    app_stack: str,
    toolkit_stack: str,
    staging_bucket: str,
    repository: str,
    qualifier: str,
    version_parameter: str,
) -> None:
    """Delete the app stack, the staging bucket and the toolkit stack; raise on leftovers."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    try:
        _delete_stack_and_wait(ctx, app_stack, timeout_s=max(30.0, deadline - time.monotonic()))
    except Exception as exc:  # noqa: BLE001 - collected and raised below
        # The app stack deletes as the toolkit's exec role: deleting the toolkit now strands it.
        raise AssertionError(
            f"app stack {app_stack} not deleted; toolkit stack {toolkit_stack} "
            f"and staging bucket {staging_bucket} kept: {exc!r}"
        ) from exc
    steps: list[tuple[str, Any]] = [
        (f"staging bucket {staging_bucket}", lambda: _empty_and_delete_bucket(ctx, staging_bucket)),
        (
            f"toolkit stack {toolkit_stack}",
            lambda: _delete_stack_and_wait(
                ctx, toolkit_stack, timeout_s=max(30.0, deadline - time.monotonic())
            ),
        ),
    ]
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - collected and raised below
            problems.append(f"{label}: {exc!r}")
    try:
        remaining = _bootstrap_remnants(ctx, staging_bucket, repository, qualifier, version_parameter)
    except ClientError as exc:
        raise AssertionError(
            f"teardown left problems behind: {problems!r}; reading bootstrap remnants failed: {exc!r}"
        ) from exc
    if remaining:
        problems.append(f"bootstrap remnants still present: {remaining!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


def _bootstrap_remnants(
    ctx, staging_bucket: str, repository: str, qualifier: str, version_parameter: str
) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    remaining: list[str] = []
    probes = (
        (
            f"staging bucket {staging_bucket}",
            ("404", "NoSuchBucket"),
            lambda: ctx.client("s3").head_bucket(Bucket=staging_bucket),
        ),
        (
            f"ssm parameter {version_parameter}",
            ("ParameterNotFound",),
            lambda: ctx.client("ssm").get_parameter(Name=version_parameter),
        ),
        (
            f"repository {repository}",
            ("RepositoryNotFoundException",),
            lambda: ctx.client("ecr").describe_repositories(repositoryNames=[repository]),
        ),
    )
    for label, absent_codes, probe in probes:
        try:
            probe()
            remaining.append(label)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in absent_codes:
                raise
    roles = [
        role["RoleName"]
        for page in ctx.client("iam").get_paginator("list_roles").paginate()
        for role in page["Roles"]
        if role["RoleName"].startswith(f"cdk-{qualifier}-")
    ]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
