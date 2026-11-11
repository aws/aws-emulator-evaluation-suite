"""cdk-deploy-role-with-attached-managed-policy-read-back-then-destroyed."""
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

CHECK = "cdk-deploy-role-with-attached-managed-policy-read-back-then-destroyed"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0
_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
# ---------------------------------------------------------------------------------------------

_APP = Path(__file__).parent / "deployments" / "cdk-iam-role-managed-policy"


@tags(
    "axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CDK-deployed IAM Role with an attached AWS-managed ManagedPolicy: GetRole and
    ListAttachedRolePolicies read back the role and the attachment; a plain `cdk destroy` then
    removes the role outright.
    """
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check deploys is missing from disk: expected app.py and cdk.json under "
        f"{_APP}, found {sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    iam = ctx.client("iam")
    acct = ctx.client("sts").get_caller_identity()["Account"]

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-xsvc-iamrolecdk-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"

    work = _stage(ctx, _APP)
    state: dict[str, Any] = {"role_name": None}
    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    _bootstrap(ctx, qualifier, toolkit)
    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, acct, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    role_name = outputs["RoleName"]
    role_arn = outputs["RoleArn"]
    state["role_name"] = role_name

    # ---- 1. GetRole reads the deployed role back -------------------------------------------
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == role_arn, (
        f"GetRole({role_name!r}) returned Arn {role['Arn']!r}, expected the stack's own output "
        f"{role_arn!r}"
    )
    trust = role["AssumeRolePolicyDocument"]
    principals = [
        s["Principal"].get("Service") for s in trust["Statement"]
        if s.get("Effect") == "Allow"
    ]
    assert "ec2.amazonaws.com" in principals, (
        f"the deployed role's trust policy statements are {trust['Statement']!r}; expected an "
        f"Allow statement trusting Service ec2.amazonaws.com"
    )

    # ---- 2. THE HEADLINE: ListAttachedRolePolicies names the managed policy ---------------
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    attached_arns = sorted(p["PolicyArn"] for p in attached)
    assert attached_arns == [_MANAGED_POLICY_ARN], (
        f"ListAttachedRolePolicies({role_name!r}) returned {attached_arns!r}, expected exactly "
        f"[{_MANAGED_POLICY_ARN!r}]"
    )

    # ---- 3. cdk destroy, in-band, is the graded teardown -----------------------------------
    _cdk(ctx, work, ["destroy", "--force"], qualifier, stack, acct,
         timeout_s=_TEARDOWN_DEADLINE_S, expect_rc=0)

    # ---- 4. the role is gone through its own API -------------------------------------------
    code, message = _error(lambda: iam.get_role(RoleName=role_name))
    assert (code, message) == (
        "NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"after cdk destroy, GetRole({role_name!r}) returned {code!r}: {message!r}, expected an "
        f"outright NoSuchEntity"
    )


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the on-disk CDK app to a temp workdir so cdk.out / cdk.context.json / out.json are
    never written next to the check."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkiamrole-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _error(fn):
    """The captured AWS (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    r = subprocess.run(
        ["cdk", "bootstrap", f"aws://{acct}/{ctx.region}", "--qualifier", qualifier,
         "--toolkit-stack-name", toolkit,
         "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci"],
        cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, acct: str, *,
         timeout_s: float, expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = CHECK
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices",
           "--app", f"{sys.executable} app.py"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 240.0) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} is {status!r} after DeleteStack, expected DELETE_COMPLETE"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _teardown(ctx, stack: str, staging: str, toolkit: str, qualifier: str,
              state: dict[str, Any]) -> None:
    """Safety net for the in-band `cdk destroy` above: idempotent against a run that already
    destroyed everything, and raises naming whatever is still present otherwise."""
    errors: list[str] = []
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    for label, fn in (
        (f"app stack {stack}", lambda: _delete_stack_and_wait(ctx, stack)),
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
    ):
        if errors:
            raise AssertionError(f"toolkit stack {toolkit} and staging bucket {staging} kept: "
                                  + "; ".join(errors))
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - collected and raised below, every step still runs
            errors.append(f"{label}: {exc!r}")

    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining: list[str] = ["teardown verification never ran"]
    while time.monotonic() < deadline:
        remaining = []
        try:
            st = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"app stack {st}")
        except ClientError as exc:
            if exc.response["Error"]["Message"] != f"Stack with id {stack} does not exist":
                raise
        try:
            st = cfn.describe_stacks(StackName=toolkit)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"toolkit stack {st}")
        except ClientError as exc:
            if exc.response["Error"]["Message"] != f"Stack with id {toolkit} does not exist":
                raise
        try:
            s3.head_bucket(Bucket=staging)
            remaining.append(f"staging bucket {staging} still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "404":
                raise
        try:
            ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append("bootstrap version parameter still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
        if state.get("role_name"):
            try:
                iam.get_role(RoleName=state["role_name"])
                remaining.append(f"role {state['role_name']} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        if not remaining:
            break
        time.sleep(10.0)
    else:
        errors.append(f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")

    if errors:
        raise AssertionError(f"teardown failed to converge: {errors!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
