"""cdk-bootstrap-omitted-execution-policies-default-to-admin-for-a-lambda-deploy."""

from __future__ import annotations

import base64
import hashlib
import json
import re
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

CHECK = "cdk-bootstrap-omitted-execution-policies-default-to-admin-for-a-lambda-deploy"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam", "lambda", "logs", "s3", "ssm"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 300.0
_SHOW_TEMPLATE_TIMEOUT_S = 60.0
# A cdk step ends this long before the runner's budget, so it fails with its own message.
_RESERVE_S = 15.0
_TEARDOWN_S = 420.0
_POLL_S = 5.0
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices", "--no-color")
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
_CFN_READ_ONLY = "arn:aws:iam::aws:policy/AWSCloudFormationReadOnlyAccess"
_READ_ONLY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
_LAMBDA_BASIC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_RESPONSE = {"response": "hello, dear asset!"}
_HANDLER_JS = """\
exports.handler = async function(event) {
  const response = require('./response.json');
  return response;
};
"""
# The app: one DefaultStackSynthesizer stack holding a Node.js function packaged as a file asset.
_APP_PY = """\
import os

import aws_cdk as cdk
from aws_cdk import aws_lambda as lambda_

app = cdk.App()
stack = cdk.Stack(app, os.environ["STACK_NAME"], synthesizer=cdk.DefaultStackSynthesizer())
fn = lambda_.Function(
    stack,
    "my-function",
    code=lambda_.Code.from_asset("lambda"),
    runtime=lambda_.Runtime.NODEJS_LATEST,
    handler="index.handler",
)
cdk.CfnOutput(stack, "FunctionArn", value=fn.function_arn)
app.synth()
"""
_DEFAULT_POLICY_WARNING = (
    "Using default execution policy of 'arn:aws:iam::aws:policy/AdministratorAccess'. "
    "Pass '--cloudformation-execution-policies' to customize."
)


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
    """Bootstrapping without execution policies attaches AdministratorAccess to the exec role.

    A file-asset Lambda stack then deploys as that role; Lambda holds the published zip (hash and
    size) and Invoke returns the asset's response.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")
    state = _toolkit_state(ctx, ctx.unique_name("q")[:10], ctx.unique_name("sim2real-cdktk-"))
    state["app_stack"] = ctx.unique_name("sim2real-cdklambda-")
    scratch = _scratch(ctx, "sim2real-cdkboot-")
    template = _bootstrap_template(ctx, scratch)
    work = _scratch(ctx, "sim2real-cdkapp-")
    (work / "app.py").write_text(_APP_PY)
    _write_lambda_asset(work)

    # 1. bootstrap without --cloudformation-execution-policies. Teardown first, so a part-way
    # bootstrap or deploy is removed.
    ctx.on_cleanup(lambda: _teardown_modern(ctx, state))
    output = _bootstrap_modern(ctx, scratch, state, "--tags", f"sim2real={CHECK}")
    assert _DEFAULT_POLICY_WARNING in output, (
        f"bootstrap output lacks {_DEFAULT_POLICY_WARNING!r}; tail: {output[-1200:]!r}"
    )
    _assert_modern_toolkit(
        ctx,
        state,
        template,
        exec_policies=[],
        user_tags=[("sim2real", CHECK)],
        status="CREATE_COMPLETE",
    )

    # 2. deploy the file-asset stack through that toolkit
    _deploy_app(ctx, work, state, state["toolkit"])
    app_template = _assert_deployed_app(ctx, state, work, exec_role=True)

    # 3. the function runs the published asset
    _assert_function_runs_asset(ctx, state, work, app_template)


def _scratch(ctx, prefix: str) -> Path:
    """A temp dir of this check's own, removed after it."""
    path = Path(tempfile.mkdtemp(prefix=prefix))
    ctx.on_cleanup(lambda: shutil.rmtree(path, ignore_errors=True))
    return path


def _run_cdk(
    ctx, cwd: Path, args: list[str], *, timeout_s: float, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """Run the CDK CLI in *cwd* and require exit code 0."""
    ctx.verify_account_safety()
    full_env = ctx.subprocess_env()
    full_env.update(env or {})
    result = subprocess.run(
        ["cdk", *args, *_CDK_FLAGS],
        cwd=cwd,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=_step_timeout(ctx, timeout_s),
    )
    assert result.returncode == 0, (
        f"`cdk {' '.join(args[:2])}` exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1500:]!r}"
    )
    return result


def _user_tags(tags: list[dict[str, str]]) -> list[tuple[str, str]]:
    """Tags as sorted (key, value) pairs, without the `aws:` keys AWS reserves for itself."""
    return sorted((t["Key"], t["Value"]) for t in tags if not t["Key"].startswith("aws:"))


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
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if _stack_missing(exc, stack):
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
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED")
        time.sleep(_POLL_S)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_bucket(ctx, bucket: str) -> None:
    """Purge every object version and delete marker of *bucket*."""
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})


def _bucket_absent(ctx, bucket: str) -> bool:
    try:
        ctx.client("s3").head_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("404", "NoSuchBucket"):
            return True
        raise
    return False


def _toolkit_state(ctx, qualifier: str, toolkit: str) -> dict[str, Any]:
    """Every name the modern bootstrap template derives from *qualifier*."""
    account, region = ctx.account, ctx.region
    return {
        "qualifier": qualifier,
        "toolkit": toolkit,
        "bucket": f"cdk-{qualifier}-assets-{account}-{region}",
        "repository": f"cdk-{qualifier}-container-assets-{account}-{region}",
        "parameter": f"/cdk-bootstrap/{qualifier}/version",
        "roles": {r: f"cdk-{qualifier}-{r}-{account}-{region}" for r in _ROLES},
        "app_stack": None,
    }


def _role_arn(ctx, state: dict[str, Any], role: str) -> str:
    return f"arn:aws:iam::{ctx.account}:role/{state['roles'][role]}"


def _bootstrap_modern(ctx, cwd: Path, state: dict[str, Any], *flags: str) -> str:
    """`cdk bootstrap` with the modern template for this run's qualifier; returns its output."""
    result = _run_cdk(
        ctx,
        cwd,
        [
            "bootstrap",
            f"aws://{ctx.account}/{ctx.region}",
            "--toolkit-stack-name",
            state["toolkit"],
            "--qualifier",
            state["qualifier"],
            *flags,
        ],
        timeout_s=_BOOTSTRAP_TIMEOUT_S,
        env={"CDK_NEW_BOOTSTRAP": "1"},
    )
    return result.stdout + result.stderr


def _bootstrap_template(ctx, cwd: Path) -> dict[str, Any]:
    """The installed CLI's modern bootstrap template, read offline."""
    result = _run_cdk(
        ctx, cwd, ["bootstrap", "--show-template", "--json"], timeout_s=_SHOW_TEMPLATE_TIMEOUT_S
    )
    # The CLI may write a notice line before the JSON object.
    return json.loads(result.stdout[result.stdout.index("{") :])


def _assert_modern_toolkit(
    ctx,
    state: dict[str, Any],
    template: dict[str, Any],
    *,
    exec_policies: list[str],
    user_tags: list[tuple[str, str]],
    status: str,
    extra_outputs: dict[str, str] | None = None,
    managed: dict[str, list[str]] | None = None,
) -> None:
    """The toolkit stack and every resource it declares, each read through its own service."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    ecr = ctx.client("ecr")
    iam = ctx.client("iam")
    account, region, qualifier = ctx.account, ctx.region, state["qualifier"]
    bucket, repository, parameter = state["bucket"], state["repository"], state["parameter"]
    resources = template["Resources"]
    version = resources["CdkBootstrapVersion"]["Properties"]["Value"]

    # CloudFormation's view: status, tags, outputs and the parameters the CLI passed.
    stack = cfn.describe_stacks(StackName=state["toolkit"])["Stacks"][0]
    assert stack["StackStatus"] == status, (
        f"toolkit stack is {stack['StackStatus']!r}, expected {status!r}"
    )
    assert _user_tags(stack.get("Tags", [])) == user_tags, (
        f"toolkit stack tags are {stack.get('Tags')!r}, expected {user_tags!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    _assert_bucket_domain(ctx, outputs.pop("BucketDomainName", ""), bucket)
    assert outputs == {
        "BucketName": bucket,
        "FileAssetKeyArn": "AWS_MANAGED_KEY",
        "ImageRepositoryName": repository,
        "BootstrapVersion": version,
        **(extra_outputs or {}),
    }, f"toolkit stack outputs are {outputs!r}"
    parameters = {p["ParameterKey"]: p.get("ParameterValue") for p in stack.get("Parameters", [])}
    expected_parameters = {
        "Qualifier": qualifier,
        "FileAssetsBucketKmsKeyId": "AWS_MANAGED_KEY",
        "CloudFormationExecutionPolicies": ",".join(exec_policies),
        "PublicAccessBlockConfiguration": "true",
        "InputPermissionsBoundary": "",
    }
    got_parameters = {k: parameters.get(k) for k in expected_parameters}
    assert got_parameters == expected_parameters, (
        f"toolkit stack parameters are {got_parameters!r}, expected {expected_parameters!r}"
    )

    # The version parameter.
    value = _version_parameter(ctx, parameter)
    assert (value["Type"], value["Value"]) == ("String", version), (
        f"{parameter!r} is {value['Type']!r} {value['Value']!r}, expected 'String' {version!r}"
    )
    ssm_tags = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=parameter)
    assert _user_tags(ssm_tags.get("TagList", [])) == user_tags, (
        f"{parameter!r} tags are {ssm_tags.get('TagList')!r}, expected {user_tags!r}"
    )

    # The staging bucket.
    versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert versioning == "Enabled", f"staging bucket versioning is {versioning!r}"
    block = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert block == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }, f"staging bucket public access block is {block!r}, expected all four True"
    rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    # The template's settings only: S3 adds its own, such as the encryption types it blocks.
    keys = ("ApplyServerSideEncryptionByDefault", "BucketKeyEnabled")
    defaults = [{k: r.get(k) for k in keys} for r in rules]
    assert defaults == _KMS_DEFAULT_RULES, (
        f"staging bucket encryption rules are {rules!r}, expected {_KMS_DEFAULT_RULES!r}"
    )
    statements = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])["Statement"]
    bucket_arn = f"arn:aws:s3:::{bucket}"
    got_statements = [
        (s.get("Sid"), s.get("Effect"), s.get("Principal"), s.get("Action"))
        + (sorted(s.get("Resource", [])), s.get("Condition"))
        for s in statements
    ]
    assert got_statements == [
        (
            "AllowSSLRequestsOnly",
            "Deny",
            "*",
            "s3:*",
            [bucket_arn, f"{bucket_arn}/*"],
            {"Bool": {"aws:SecureTransport": "false"}},
        )
    ], f"staging bucket policy statements are {statements!r}"
    _assert_lifecycle(ctx, bucket, template)
    assert _user_tags(s3.get_bucket_tagging(Bucket=bucket)["TagSet"]) == user_tags, (
        f"staging bucket tags differ from {user_tags!r}"
    )

    # The container-asset repository.
    repo_props = resources["ContainerAssetsRepository"]["Properties"]
    repos = ecr.describe_repositories(repositoryNames=[repository])["repositories"]
    assert [(r["repositoryName"], r["imageTagMutability"]) for r in repos] == [
        (repository, "IMMUTABLE")
    ], f"describe_repositories({repository!r}) returned {repos!r}"
    lifecycle_text = ecr.get_lifecycle_policy(repositoryName=repository)["lifecyclePolicyText"]
    assert json.loads(lifecycle_text) == json.loads(
        repo_props["LifecyclePolicy"]["LifecyclePolicyText"]
    ), f"repository lifecycle policy is {lifecycle_text!r}"
    repo_policy = json.loads(ecr.get_repository_policy(repositoryName=repository)["policyText"])
    got_repo_policy = [
        (s.get("Sid"), s.get("Effect"), s.get("Principal"), sorted(s.get("Action", [])))
        for s in repo_policy["Statement"]
    ]
    want_repo_policy = [
        (s["Sid"], s["Effect"], s["Principal"], sorted(s["Action"]))
        for s in repo_props["RepositoryPolicyText"]["Statement"]
    ]
    assert got_repo_policy == want_repo_policy, f"repository policy is {repo_policy!r}"
    repo_tags = ecr.list_tags_for_resource(resourceArn=repos[0]["repositoryArn"])["tags"]
    assert _user_tags(repo_tags) == user_tags, (
        f"repository tags are {repo_tags!r}, expected {user_tags!r}"
    )

    # Exactly the five bootstrap roles, each with its trust, policies and tags.
    names = sorted(
        r["RoleName"]
        for page in iam.get_paginator("list_roles").paginate()
        for r in page["Roles"]
        if r["RoleName"].startswith(f"cdk-{qualifier}-")
    )
    assert names == sorted(state["roles"].values()), (
        f"roles for qualifier {qualifier!r} are {names!r}, expected the five bootstrap roles"
    )
    root = f"arn:aws:iam::{account}:root"
    account_trust = [
        {
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {"AWS": root},
            "Condition": {"Null": {"sts:ExternalId": "true"}},
        },
        {"Action": "sts:TagSession", "Effect": "Allow", "Principal": {"AWS": root}},
    ]
    exec_trust = [
        {
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "cloudformation.amazonaws.com"},
        }
    ]
    policy_name = f"cdk-{qualifier}-{{}}-default-policy-{account}-{region}"
    expected_roles = {
        "cfn-exec-role": (exec_trust, sorted(exec_policies or [_ADMIN]), [], None),
        "deploy-role": (account_trust, [_CFN_READ_ONLY], ["default"], "deploy"),
        "file-publishing-role": (
            account_trust,
            [],
            [policy_name.format("file-publishing-role")],
            "file-publishing",
        ),
        "image-publishing-role": (
            account_trust,
            [],
            [policy_name.format("image-publishing-role")],
            "image-publishing",
        ),
        "lookup-role": (account_trust, [_READ_ONLY], ["LookupRolePolicy"], "lookup"),
    }
    for role, (trust, want_managed, inline, kind) in expected_roles.items():
        want_managed = (managed or {}).get(role, want_managed)
        name = state["roles"][role]
        got = iam.get_role(RoleName=name)["Role"]
        assert (got["Arn"], got["Path"], got["MaxSessionDuration"]) == (
            _role_arn(ctx, state, role),
            "/",
            3600,
        ), f"{role} is {got['Arn']!r} path {got['Path']!r} max {got['MaxSessionDuration']!r}"
        assert got["AssumeRolePolicyDocument"]["Statement"] == trust, (
            f"{role} trust is {got['AssumeRolePolicyDocument']!r}, expected {trust!r}"
        )
        assert "PermissionsBoundary" not in got, (
            f"{role} has permissions boundary {got['PermissionsBoundary']!r}, expected none"
        )
        role_tags = sorted(user_tags + ([("aws-cdk:bootstrap-role", kind)] if kind else []))
        assert _user_tags(got.get("Tags", [])) == role_tags, (
            f"{role} tags are {got.get('Tags')!r}, expected {role_tags!r}"
        )
        attached = sorted(
            p["PolicyArn"]
            for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
        )
        assert attached == want_managed, (
            f"{role} managed policies are {attached!r}, expected {want_managed!r}"
        )
        inline_names = sorted(iam.list_role_policies(RoleName=name)["PolicyNames"])
        assert inline_names == inline, (
            f"{role} inline policies are {inline_names!r}, expected {inline!r}"
        )

    # Every role's inline policy documents, as the template declares them.
    _assert_role_policies(ctx, template, stack)


def _empty_repo(ctx, repository: str) -> None:
    """Delete every image, so the toolkit stack delete can remove the repository."""
    ecr = ctx.client("ecr")
    try:
        ids = [
            {"imageDigest": d["imageDigest"]}
            for page in ecr.get_paginator("describe_images").paginate(repositoryName=repository)
            for d in page["imageDetails"]
        ]
        if ids:
            ecr.batch_delete_image(repositoryName=repository, imageIds=ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge and delete the staging bucket, which the toolkit stack retains on delete."""
    try:
        _empty_bucket(ctx, bucket)
        ctx.client("s3").delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


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


def _bootstrap_remnants(ctx, state: dict[str, Any]) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    remaining: list[str] = []
    if not _bucket_absent(ctx, state["bucket"]):
        remaining.append(f"staging bucket {state['bucket']}")
    probes = (
        (
            f"ssm parameter {state['parameter']}",
            "ParameterNotFound",
            lambda: ctx.client("ssm").get_parameter(Name=state["parameter"]),
        ),
        (
            f"repository {state['repository']}",
            "RepositoryNotFoundException",
            lambda: ctx.client("ecr").describe_repositories(repositoryNames=[state["repository"]]),
        ),
    )
    for label, absent_code, probe in probes:
        try:
            probe()
            remaining.append(label)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != absent_code:
                raise
    roles = [
        role["RoleName"]
        for page in ctx.client("iam").get_paginator("list_roles").paginate()
        for role in page["Roles"]
        if role["RoleName"].startswith(f"cdk-{state['qualifier']}-")
    ]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _teardown_modern(ctx, state: dict[str, Any]) -> None:
    """Delete the app stack and its functions' log groups, then the toolkit stack and its bucket.

    Raises on any leftover.
    """
    deadline = time.monotonic() + _TEARDOWN_S

    def left() -> float:
        return max(30.0, deadline - time.monotonic())

    log_groups: list[str] = []
    if state["app_stack"]:
        log_groups = _function_log_groups(ctx, state["app_stack"])
        # The app stack deletes as the toolkit's roles: deleting the toolkit first strands it.
        _delete_stack_and_wait(ctx, state["app_stack"], timeout_s=left())
    steps: list[tuple[str, Any]] = [
        *[
            (f"log group {g}", lambda g=g: _reap_log_group(ctx, g, budget_s=min(120.0, left())))
            for g in log_groups
        ],
        (f"repository {state['repository']}", lambda: _empty_repo(ctx, state["repository"])),
        (
            f"toolkit stack {state['toolkit']}",
            lambda: _delete_stack_and_wait(ctx, state["toolkit"], timeout_s=left()),
        ),
        # The stack retains its staging bucket; its delete removes the bucket policy first.
        (
            f"staging bucket {state['bucket']}",
            lambda: _empty_and_delete_bucket(ctx, state["bucket"]),
        ),
    ]
    problems: list[str] = []
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - every step runs; collected and raised below
            problems.append(f"{label}: {exc!r}")
    # IAM lists a deleted role for a while after its delete.
    remaining = _poll(
        lambda: _bootstrap_remnants(ctx, state), lambda r: not r, budget_s=min(60.0, left())
    )
    if remaining:
        problems.append(f"bootstrap remnants still present: {remaining!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


def _deploy_app(
    ctx, work: Path, state: dict[str, Any], toolkit_name: str, env: dict[str, str] | None = None
) -> None:
    """`cdk deploy` of the app stack with the qualifier and toolkit name given as context."""
    stack = state["app_stack"]
    _run_cdk(
        ctx,
        work,
        [
            "deploy",
            "--require-approval=never",
            "--toolkit-stack-name",
            toolkit_name,
            "--context",
            f"@aws-cdk/core:bootstrapQualifier={state['qualifier']}",
            "--context",
            "@aws-cdk/core:newStyleStackSynthesis=1",
            "--progress",
            "events",
            stack,
            # The app runs under this interpreter, which has aws-cdk-lib.
            "--app",
            f"{sys.executable} app.py",
        ],
        timeout_s=_DEPLOY_TIMEOUT_S,
        env={"STACK_NAME": stack, **(env or {})},
    )


def _resolve(ctx, text: str) -> str:
    return text.replace("${AWS::AccountId}", ctx.account).replace("${AWS::Region}", ctx.region)


def _assert_deployed_app(ctx, state: dict[str, Any], work: Path, *, exec_role: bool) -> dict:
    """The app stack as CloudFormation reports it, every resource it lists, and its template asset.

    Returns the synthesized template.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack = state["app_stack"]
    template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
    deployed = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert deployed["StackStatus"] == "CREATE_COMPLETE", (
        f"app stack is {deployed['StackStatus']!r}, expected 'CREATE_COMPLETE'"
    )
    want_role = _role_arn(ctx, state, "cfn-exec-role") if exec_role else None
    assert deployed.get("RoleARN") == want_role, (
        f"app stack RoleARN is {deployed.get('RoleARN')!r}, expected {want_role!r}"
    )
    version_param = {p["ParameterKey"]: p for p in deployed.get("Parameters", [])}.get(
        "BootstrapVersion", {}
    )
    version = ctx.client("ssm").get_parameter(Name=state["parameter"])["Parameter"]["Value"]
    assert (version_param.get("ParameterValue"), version_param.get("ResolvedValue")) == (
        state["parameter"],
        version,
    ), (
        f"app stack parameter BootstrapVersion is {version_param!r}, expected "
        f"{state['parameter']!r} resolved from SSM to {version!r}"
    )
    listed = sorted(
        (r["LogicalResourceId"], r["ResourceType"], r["ResourceStatus"])
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
    )
    want = sorted((lid, r["Type"], "CREATE_COMPLETE") for lid, r in template["Resources"].items())
    assert listed == want, f"app stack resources are {listed!r}, expected {want!r}"

    # The template reached CloudFormation through the staging bucket.
    manifest = json.loads((work / "cdk.out" / f"{stack}.assets.json").read_text())
    template_assets = [
        a for a in manifest["files"].values() if a["source"].get("path") == f"{stack}.template.json"
    ]
    assert len(template_assets) == 1, f"assets manifest lists {len(template_assets)} templates"
    (destination,) = template_assets[0]["destinations"].values()
    assert (
        _resolve(ctx, destination["bucketName"]),
        _resolve(ctx, destination["assumeRoleArn"].replace("${AWS::Partition}", "aws")),
    ) == (state["bucket"], _role_arn(ctx, state, "file-publishing-role")), (
        f"template asset destination is {destination!r}"
    )
    published = s3.get_object(Bucket=state["bucket"], Key=destination["objectKey"])
    local = (work / "cdk.out" / f"{stack}.template.json").read_bytes()
    assert published["Body"].read() == local, (
        f"s3://{state['bucket']}/{destination['objectKey']} does not hold the synthesized template"
    )
    return template


def _assert_function_runs_asset(ctx, state: dict[str, Any], work: Path, template: dict) -> None:
    """The function runs the published zip asset (code hash and size) and answers an Invoke."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    stack = state["app_stack"]
    physical = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
    }
    (fn_id,) = [k for k, r in template["Resources"].items() if r["Type"] == "AWS::Lambda::Function"]
    props = template["Resources"][fn_id]["Properties"]
    fn_name = physical[fn_id]
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])
    }
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
    assert outputs.get("FunctionArn") == fn_arn, (
        f"app stack output FunctionArn is {outputs.get('FunctionArn')!r}, expected {fn_arn!r}"
    )

    # The zip asset in the staging bucket is the code Lambda holds.
    manifest = json.loads((work / "cdk.out" / f"{stack}.assets.json").read_text())
    zips = [a for a in manifest["files"].values() if a["source"].get("packaging") == "zip"]
    assert len(zips) == 1, f"assets manifest lists {len(zips)} zip assets, expected one"
    (destination,) = zips[0]["destinations"].values()
    assert _resolve(ctx, destination["bucketName"]) == state["bucket"], destination
    assert props["Code"]["S3Key"] == destination["objectKey"], (
        f"function code key {props['Code']!r} is not the asset key {destination['objectKey']!r}"
    )
    body = s3.get_object(Bucket=state["bucket"], Key=destination["objectKey"])["Body"].read()
    sha256 = base64.b64encode(hashlib.sha256(body).digest()).decode()
    config = lam.get_function(FunctionName=fn_name)["Configuration"]
    role_name = physical[props["Role"]["Fn::GetAtt"][0]]
    got = (
        config["Runtime"],
        config["Handler"],
        config["PackageType"],
        config["CodeSha256"],
        config["CodeSize"],
        config["Role"],
    )
    assert got == (
        props["Runtime"],
        "index.handler",
        "Zip",
        sha256,
        len(body),
        f"arn:aws:iam::{ctx.account}:role/{role_name}",
    ), f"GetFunction({fn_name!r}) reports {got!r}; the published asset hashes to {sha256!r}"

    # The function's service role.
    role = iam.get_role(RoleName=role_name)["Role"]
    trust = role["AssumeRolePolicyDocument"]["Statement"]
    lambda_trust = {"Service": "lambda.amazonaws.com"}
    assert trust == [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": lambda_trust}], (
        f"function role trust is {trust!r}"
    )
    attached = [
        p["PolicyArn"]
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    ]
    assert attached == [_LAMBDA_BASIC], f"function role managed policies are {attached!r}"

    # The function answers with the asset's response document.
    resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
    raw = resp["Payload"].read()
    assert (resp["StatusCode"], resp.get("FunctionError")) == (200, None), (
        f"Invoke of {fn_name!r} returned {resp['StatusCode']} {resp.get('FunctionError')!r}: "
        f"{raw[:400]!r}"
    )
    assert json.loads(raw) == _RESPONSE, f"Invoke returned {raw[:400]!r}, expected {_RESPONSE!r}"


def _write_lambda_asset(work: Path) -> None:
    """The handler directory the app packages as a zip asset."""
    (work / "lambda").mkdir()
    (work / "lambda" / "index.js").write_text(_HANDLER_JS)
    (work / "lambda" / "response.json").write_text(json.dumps(_RESPONSE, indent=2) + "\n")


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


def _assert_bucket_domain(ctx, domain: str, bucket: str) -> None:
    """The BucketDomainName output names the bucket's regional S3 host, by its labels."""
    labels = f"{bucket}.s3.{ctx.region}."
    assert domain.startswith(labels), (
        f"toolkit output BucketDomainName is {domain!r}, expected the host {labels}<domain>"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
