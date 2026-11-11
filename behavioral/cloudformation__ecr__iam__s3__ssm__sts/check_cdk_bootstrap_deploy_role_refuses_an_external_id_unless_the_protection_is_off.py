"""cdk-bootstrap-deploy-role-refuses-an-external-id-unless-the-protection-is-off."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-bootstrap-deploy-role-refuses-an-external-id-unless-the-protection-is-off"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam", "s3", "ssm", "sts"]

_BOOTSTRAP_TIMEOUT_S = 300.0
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
# The template's `Ref: AWS::NoValue`: the property or list item is left out.
_NO_VALUE = object()
# The template's SSE-KMS default with the AWS managed key; it sets no S3 Bucket Key.
_KMS_DEFAULT_RULES = [
    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": False}
]

_EXTERNAL_ID = "some-external-id"
_SESSION = "sim2real-external-id"
# A trust policy change reaches STS eventually, at times minutes after the stack update completes;
# a positive call retries AccessDenied this long, capped by the run budget.
_PROPAGATION_S = 300.0


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """The bootstrap deploy role refuses AssumeRole with an ExternalId unless the protection is off.

    By default the call is AccessDenied while one without an ExternalId succeeds; a re-bootstrap
    with `--no-deny-external-id` updates the roles in place and allows it.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-customizing.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()["Arn"]
    # The bootstrap arguments and the assumed role take the caller's partition; the graded
    # trust, role and managed-policy ARNs are those of the aws partition.
    partition = caller.split(":")[1]
    admin = f"arn:{partition}:iam::aws:policy/AdministratorAccess"

    template = _bootstrap_template(ctx)
    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    deploy_role = _toolkit_names(ctx, qualifier)["deploy-role"]
    role_arn = f"arn:{partition}:iam::{ctx.account}:role/{deploy_role}"
    ctx.on_cleanup(lambda: _teardown(ctx, toolkit_stack, qualifier))
    base = ["--qualifier", qualifier, "--cloudformation-execution-policies", admin]

    # 1. default bootstrap: the parameter is true and every trust carries the condition
    _bootstrap(ctx, toolkit_stack, base)
    first = _stack(ctx, toolkit_stack)
    got = _parameters(first).get("DenyExternalId")
    assert got == "true", f"{toolkit_stack} DenyExternalId is {got!r}, expected 'true'"
    protected = _assert_bootstrap_roles(
        ctx, qualifier, exec_policies=(admin,), deny_external_id=True
    )
    _assert_toolkit(ctx, toolkit_stack, qualifier, template, status="CREATE_COMPLETE")

    # 2. protected role: assumable without an ExternalId, refused with one
    _assume_and_identify(ctx, role_arn)
    refused = _error(
        lambda: sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=_SESSION,
            ExternalId=_EXTERNAL_ID,
            DurationSeconds=900,
        )
    )
    want = (
        "AccessDenied",
        f"User: {caller} is not authorized to perform: sts:AssumeRole on resource: {role_arn}",
    )
    assert refused == want, f"AssumeRole with an ExternalId returned {refused!r}, expected {want!r}"

    # 3. re-bootstrap with `--no-deny-external-id`: the trusts drop the condition in place
    _bootstrap(ctx, toolkit_stack, [*base, "--no-deny-external-id"])
    second = _stack(ctx, toolkit_stack)
    got = (second["StackId"], _parameters(second).get("DenyExternalId"))
    assert got == (first["StackId"], "false"), (
        f"{toolkit_stack} (StackId, DenyExternalId) is {got!r}, expected "
        f"({first['StackId']!r}, 'false')"
    )
    unprotected = _assert_bootstrap_roles(
        ctx, qualifier, exec_policies=(admin,), deny_external_id=False
    )
    replaced = sorted(r for r in protected if unprotected[r]["RoleId"] != protected[r]["RoleId"])
    assert replaced == [], (
        f"the re-bootstrap replaced roles {replaced!r}; expected in-place updates"
    )
    _assert_toolkit(ctx, toolkit_stack, qualifier, template, status="UPDATE_COMPLETE")

    # 4. the same ExternalId call is now allowed
    _assume_and_identify(ctx, role_arn, ExternalId=_EXTERNAL_ID)


def _assume_and_identify(ctx, role_arn: str, **extra) -> None:
    """AssumeRole must succeed, and the session's own identity must be that role session.

    AccessDenied is retried until the trust policy change propagates, bounded by the run budget.
    """
    sts = ctx.client("sts")
    timeout = _budget_s(ctx, _PROPAGATION_S)
    deadline = time.monotonic() + timeout
    while True:
        try:
            response = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION, DurationSeconds=900, **extra
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") != "AccessDenied":
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"run budget ended waiting to assume {role_arn}") from exc
                raise AssertionError(
                    f"AssumeRole {role_arn} with {extra!r} still AccessDenied after "
                    f"{timeout:.0f}s: {err.get('Message')!r}"
                ) from exc
            time.sleep(_POLL_S)
    role_name = role_arn.rpartition("/")[2]
    partition = role_arn.split(":")[1]
    session_arn = f"arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION}"
    assert response["AssumedRoleUser"]["Arn"] == session_arn, (
        f"AssumeRole returned user {response['AssumedRoleUser']['Arn']!r}, expected {session_arn!r}"
    )
    credentials = response["Credentials"]
    as_role = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretAccessKey"],
            "aws_session_token": credentials["SessionToken"],
        },
    )
    identity = as_role.get_caller_identity()["Arn"]
    assert identity == session_arn, (
        f"the assumed session calls itself {identity!r}, expected {session_arn!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, capped by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _stack(ctx, name: str) -> dict[str, Any]:
    return ctx.client("cloudformation").describe_stacks(StackName=name)["Stacks"][0]


def _parameters(stack: dict[str, Any]) -> dict[str, str]:
    """A stack's parameters by key; an empty value may be returned without ParameterValue."""
    return {p["ParameterKey"]: p.get("ParameterValue", "") for p in stack.get("Parameters", [])}


def _outputs(stack: dict[str, Any]) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _expected_trust(ctx, role: str, *, deny_external_id: bool) -> list[dict[str, Any]]:
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
            assume["Condition"] = {"Null": {"sts:ExternalId": ["true"]}}
        assume["Principal"] = principal
        return [assume, {"Effect": "Allow", "Action": ["sts:TagSession"], "Principal": principal}]

    return pair([ctx.account])


def _assert_bootstrap_roles(
    ctx,
    qualifier: str,
    *,
    exec_policies: tuple[str, ...],
    deny_external_id: bool,
) -> dict[str, dict[str, Any]]:
    """IAM's view of the five bootstrap roles: ARN, trust, no boundary, policies; returns them."""
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
        trust = _policy_statements(got["AssumeRolePolicyDocument"])
        want = _expected_trust(ctx, role, deny_external_id=deny_external_id)
        assert trust == want, f"{role} trust statements are {trust!r}, expected {want!r}"
        assert got.get("PermissionsBoundary") is None, (
            f"{role} permissions boundary is {got.get('PermissionsBoundary')!r}, expected none"
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


def _assert_staging_bucket(ctx, bucket: str, template: dict[str, Any]) -> None:
    """S3's view of the staging bucket *template* built: versioning, lifecycle, access, KMS, TLS."""
    s3 = ctx.client("s3")
    versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert versioning == "Enabled", (
        f"bucket {bucket} versioning is {versioning!r}, expected Enabled"
    )
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
    statements = _policy_statements(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    assert statements == [
        {
            "Effect": "Deny",
            "Sid": "AllowSSLRequestsOnly",
            "Condition": {"Bool": {"aws:SecureTransport": ["false"]}},
            "Action": ["s3:*"],
            "Resource": sorted([arn, f"{arn}/*"]),
            "Principal": "*",
        }
    ], f"bucket {bucket} policy statements are {statements!r}"


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) a call raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError(f"call succeeded but was expected to be refused; returned {result!r}")


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


def _teardown(ctx, toolkit_stack: str, qualifier: str) -> None:
    """Delete the toolkit stack, then the repository images and bucket it keeps.

    Raises on any leftover.
    """
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S

    def left() -> float:
        return max(30.0, deadline - time.monotonic())

    names = _toolkit_names(ctx, qualifier)
    problems: list[str] = []
    steps: list[tuple[str, Any]] = [
        (f"repository {names['repository']}", lambda: _empty_repository(ctx, names["repository"])),
        (
            f"toolkit stack {toolkit_stack}",
            lambda: _delete_stack_and_wait(ctx, toolkit_stack, timeout_s=left()),
        ),
        # The stack retains its staging bucket; its delete removes the bucket policy first.
        (f"bucket {names['bucket']}", lambda: _empty_and_delete_bucket(ctx, names["bucket"])),
    ]
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - collected and raised below
            problems.append(f"{label}: {exc!r}")
    try:
        # IAM reports a deleted role or policy for a while after its delete.
        remaining = _poll(
            lambda: _remnants(ctx, qualifier),
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


def _remnants(ctx, qualifier: str) -> list[str]:
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
        (
            f"bucket {names['bucket']}",
            ("404", "NoSuchBucket"),
            lambda: ctx.client("s3").head_bucket(Bucket=names["bucket"]),
        ),
        *[
            (
                f"role {names[r]}",
                ("NoSuchEntity",),
                lambda r=r: ctx.client("iam").get_role(RoleName=names[r]),
            )
            for r in _ROLES
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


def _assert_bucket_domain(ctx, domain: str, bucket: str) -> None:
    """The BucketDomainName output names the bucket's regional S3 host, by its labels."""
    labels = f"{bucket}.s3.{ctx.region}."
    assert domain.startswith(labels), (
        f"toolkit output BucketDomainName is {domain!r}, expected the host {labels}<domain>"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
