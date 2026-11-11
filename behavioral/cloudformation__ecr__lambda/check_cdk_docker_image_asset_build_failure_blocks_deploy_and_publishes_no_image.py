"""cdk-docker-image-asset-build-failure-blocks-deploy-and-publishes-no-image."""
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

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-docker-image-asset-build-failure-blocks-deploy-and-publishes-no-image"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "lambda"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_DESTROY_TIMEOUT_S = 600.0
_TEARDOWN_S = 420.0
_POLL_S = 5.0
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")

_APP_PY = '''\
import os
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda


class ImageStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        fn = _lambda.DockerImageFunction(
            self, "ImgFn",
            code=_lambda.DockerImageCode.from_image_asset(directory="image"),
            timeout=cdk.Duration.seconds(30),
            memory_size=512,
        )
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)


app = cdk.App()
ImageStack(app, os.environ["STACK_NAME"],
           synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
           env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                               region=os.environ["CDK_DEFAULT_REGION"]))
app.synth()
'''

_BROKEN_DOCKERFILE = '''\
FROM public.ecr.aws/lambda/python:3.12
COPY app.py ${LAMBDA_TASK_ROOT}
RUN false
CMD ["app.handler"]
'''

_WORKING_DOCKERFILE = '''\
FROM public.ecr.aws/lambda/python:3.12
COPY app.py ${LAMBDA_TASK_ROOT}
CMD ["app.handler"]
'''

_HANDLER_PY = '''\
def handler(event, context):
    return {"marker": "%s"}
'''


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Docker image asset whose build fails locally refuses `cdk deploy` before any changeset or
    push, leaving the stack unborn and the computed content-hash tag absent from the registry; the
    same app with a corrected Dockerfile then deploys and serves normally.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/images-create.html
    """
    require_tools("cdk", "docker")
    ctx.verify_account_safety()
    _assert_docker_daemon_alive()
    ecr = ctx.client("ecr")
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-cdkimgbad-")
    repo_name = f"cdk-{qualifier}-container-assets-{ctx.account}-{ctx.region}"
    state: dict[str, Any] = {
        "qualifier": qualifier, "toolkit": ctx.unique_name("sim2real-cdktk-"),
        "staging": f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}",
        "repo": repo_name, "stack": stack, "destroyed": False, "log_group": None,
    }

    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkimgbad-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    (work / "image").mkdir()
    (work / "cdk.json").write_text(json.dumps({"app": f"{sys.executable} app.py"}))
    (work / "app.py").write_text(_APP_PY)
    (work / "image" / "app.py").write_text(_HANDLER_PY % "unreachable")

    # Registered before bootstrap, so a half-finished bootstrap or deploy is still torn down.
    ctx.on_cleanup(lambda: _teardown(ctx, state))
    _bootstrap(ctx, state)

    # The asset's content hash is computed from the build CONTEXT, not from a successful
    # build, so `cdk synth` alone (no docker invoked) gives the tag the broken build would
    # have published under.
    (work / "image" / "Dockerfile").write_text(_BROKEN_DOCKERFILE)
    _cdk(ctx, work, ["synth", "--quiet"], state, timeout_s=120.0, expect_rc=0)
    broken_hash = _image_hash(work, stack)

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], state,
                   timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
    assert rc != 0, (
        f"`cdk deploy` exited 0 with a Dockerfile whose `RUN false` fails every build — the "
        f"local build must be refused before anything is published. Output tail: {out[-800:]!r}"
    )
    assert "docker" in out.lower() and ("exit code: 1" in out or "exit status 1" in out.lower()
                                        or "returned a non-zero code" in out.lower()), (
        f"deploy failed but the output does not name a docker build failure with exit code 1; "
        f"output tail: {out[-1200:]!r}"
    )

    # effect-absent: no stack, and the computed tag never reached the registry.
    exc = _client_error(lambda: cfn.describe_stacks(StackName=stack))
    assert exc.response["Error"]["Code"] == "ValidationError", (
        f"DescribeStacks on {stack!r} returned {exc.response['Error']['Code']!r}, expected "
        f"ValidationError for a stack that was never created"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        exc.response["Error"]["Message"]
    )
    exc = _client_error(lambda: ecr.describe_images(repositoryName=repo_name,
                                                    imageIds=[{"imageTag": broken_hash}]))
    code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    assert code == "ImageNotFoundException", (
        f"the refused build's tag {broken_hash!r} describes as code {code!r} in {repo_name!r}, "
        f"expected ImageNotFoundException"
    )
    assert message == (
        f"The image with imageId {{imageDigest:'null', imageTag:'{broken_hash}'}} does not "
        f"exist within the repository with name '{repo_name}' in the registry with id "
        f"'{ctx.account}'"
    ), message

    # Positive control: the identical app with a fixed Dockerfile deploys and serves, proving
    # the broken instruction (and not the qualifier, role or network) was the cause.
    (work / "image" / "Dockerfile").write_text(_WORKING_DOCKERFILE)
    _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", "--outputs-file",
                     "out.json"], state, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    fn_name = json.loads((work / "out.json").read_text())[stack]["FunctionName"]
    state["log_group"] = f"/aws/lambda/{fn_name}"
    fixed_hash = _image_hash(work, stack)
    assert fixed_hash != broken_hash, (
        f"the fixed Dockerfile hashed to the same context key {fixed_hash!r} as the broken one"
    )
    resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
    raw = resp["Payload"].read()
    assert "FunctionError" not in resp, f"invoke of {fn_name!r} errored: {raw[:400]!r}"
    payload = json.loads(raw)
    assert payload == {"marker": "unreachable"}, (
        f"control: invoke of the working image returned {payload!r}, expected "
        f"{{'marker': 'unreachable'}}"
    )

    _cdk(ctx, work, ["destroy", stack, "--force"], state, timeout_s=_DESTROY_TIMEOUT_S,
         expect_rc=0)
    state["destroyed"] = True
    gone = _client_error(lambda: cfn.describe_stacks(StackName=stack))
    assert gone.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        f"DescribeStacks after `cdk destroy`: {gone.response['Error']!r}"
    )


def _assert_docker_daemon_alive() -> None:
    """A dead daemon fails loudly here, not as an opaque non-zero rc several minutes into deploy."""
    r = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"docker daemon unreachable: {r.stderr.strip()[-400:]!r}"


def _image_hash(work: Path, stack: str) -> str:
    """The image asset's content-hash key from the synthesized asset manifest."""
    assets = json.loads((work / "cdk.out" / f"{stack}.assets.json").read_text())
    images = assets["dockerImages"]
    ids = [k for k, v in images.items() if v.get("displayName") == "ImgFn/AssetImage"]
    assert len(ids) == 1, f"expected one 'ImgFn/AssetImage' docker asset, manifest had {ids!r}"
    return ids[0]


def _client_error(fn) -> ClientError:
    """The ClientError a call raises."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _bootstrap(ctx, state: dict) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}",
        "--qualifier", state["qualifier"],
        "--toolkit-stack-name", state["toolkit"],
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--tags", f"sim2real={CHECK}",
        *_CDK_FLAGS,
    ]
    r = subprocess.run(cmd, cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
                       timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], state: dict, *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work* against this run's qualifier and stack."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env.update({"CDK_DEFAULT_REGION": ctx.region, "CDK_DEFAULT_ACCOUNT": ctx.account,
                "Q": state["qualifier"], "STACK_NAME": state["stack"]})
    r = subprocess.run(["cdk", *args, *_CDK_FLAGS], cwd=work, env=env, capture_output=True,
                       text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _stack_missing(exc: ClientError) -> bool:
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _stack_missing(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(_POLL_S)
    raise AssertionError(f"stack {stack!r} not deleted within {timeout_s}s (last {status!r})")


def _reap_log_group(logs, name: str, *, reads: int = 3, budget_s: float = 180.0) -> None:
    """Delete log group `name` until `reads` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
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
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"log group {name!r} still present after {budget_s}s")
            time.sleep(_POLL_S)


def _empty_repo(ctx, repo_name: str) -> None:
    """Delete every image, so the toolkit stack delete can remove the repository."""
    ecr = ctx.client("ecr")
    try:
        ids = [
            {"imageDigest": d["imageDigest"]}
            for page in ecr.get_paginator("describe_images").paginate(repositoryName=repo_name)
            for d in page["imageDetails"]
        ]
        if ids:
            ecr.batch_delete_image(repositoryName=repo_name, imageIds=ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge every version, then the bucket: StagingBucket has DeletionPolicy Retain."""
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


def _bootstrap_remnants(ctx, state: dict) -> list[str]:
    """What bootstrap left behind, by exact name."""
    qualifier = state["qualifier"]
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(
            StackName=state["toolkit"])["Stacks"][0]["StackStatus"]
        if status != "DELETE_COMPLETE":
            remaining.append(f"toolkit stack {state['toolkit']} in {status}")
    except ClientError as exc:
        if not _stack_missing(exc):
            raise
    try:
        ctx.client("s3").head_bucket(Bucket=state["staging"])
        remaining.append(f"staging bucket {state['staging']}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise
    try:
        ctx.client("ecr").describe_repositories(repositoryNames=[state["repo"]])
        remaining.append(f"container-assets repo {state['repo']}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise
    try:
        ctx.client("ssm").get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append("bootstrap version parameter")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    iam = ctx.client("iam")
    roles = [role["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for role in page["Roles"] if role["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _teardown(ctx, state: dict) -> None:
    """Delete the app stack, log group, images, Retain staging bucket and toolkit stack.

    Raises naming everything left behind.
    """
    end = time.monotonic() + _TEARDOWN_S

    def left(reserve: float = 0.0) -> float:
        return max(1.0, end - reserve - time.monotonic())

    if not state["destroyed"]:
        # The app stack deletes through the toolkit's execution role, so it goes first and a
        # failure stops here rather than strand it behind a deleted toolkit.
        _delete_stack_and_wait(ctx, state["stack"], timeout_s=left(300.0))

    def check_remnants() -> None:
        remaining = _bootstrap_remnants(ctx, state)
        if remaining:
            raise AssertionError(f"bootstrap remnants still present: {remaining!r}")

    steps: list[tuple[str, Any]] = []
    if state["log_group"]:
        steps.append((f"log group {state['log_group']}",
                      lambda: _reap_log_group(ctx.client("logs"), state["log_group"],
                                              budget_s=min(180.0, left(180.0)))))
    steps += [
        (f"container-assets repo {state['repo']}", lambda: _empty_repo(ctx, state["repo"])),
        ("staging bucket", lambda: _empty_and_delete_bucket(ctx, state["staging"])),
        (f"toolkit stack {state['toolkit']}",
         lambda: _delete_stack_and_wait(ctx, state["toolkit"], timeout_s=left())),
        ("bootstrap remnants", check_remnants),
    ]
    errors: list[str] = []
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — every step runs; collected, raised below
            errors.append(f"{label}: {exc!r}")
    if errors:
        raise AssertionError("teardown left residue: " + "; ".join(errors))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
