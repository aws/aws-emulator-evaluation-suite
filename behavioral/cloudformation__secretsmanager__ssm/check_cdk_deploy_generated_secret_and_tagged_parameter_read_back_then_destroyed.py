"""cdk-deploy-generated-secret-and-tagged-parameter-read-back-then-destroyed."""
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

CHECK = "cdk-deploy-generated-secret-and-tagged-parameter-read-back-then-destroyed"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager", "ssm"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0
# ---------------------------------------------------------------------------------------------

_APP = Path(__file__).parent / "deployments" / "cdk-secret-param"
_PARAM_VALUE = "sim2real-cdk-secret-param-placeholder"


@tags(
    "axis:happy-path", "cap:c1", "concern:data-plane", "concern:deploy",
    "concern:representation", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A CDK-deployed generated SecretsManager Secret and a tagged plain SSM StringParameter:
    GetSecretValue, GetParameter and SSM's ListTagsForResource read back their declared value
    and tags; a plain `cdk destroy` then removes both outright.
    """
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check deploys is missing from disk: expected app.py and cdk.json under "
        f"{_APP}, found {sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    sm = ctx.client("secretsmanager")
    ssm = ctx.client("ssm")
    acct = ctx.account

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-xsvc-smssmcdk-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"

    work = _stage(ctx, _APP)
    state: dict[str, Any] = {"secret_arn": None, "param_name": None}
    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    _bootstrap(ctx, qualifier, toolkit)
    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, acct, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    secret_arn = outputs["SecretArn"]
    param_name = outputs["ParamName"]
    state["secret_arn"] = secret_arn
    state["param_name"] = param_name

    # ---- 1. the generated secret reads back with its declared length ----------------------
    secret_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert len(secret_value) == 40, (
        f"the stack declares GenerateSecretString password_length=40; Secrets Manager produced a "
        f"{len(secret_value)}-character secret"
    )

    # ---- 2. the plain parameter reads back its declared value -----------------------------
    param = ssm.get_parameter(Name=param_name)["Parameter"]
    assert param["Value"] == _PARAM_VALUE, (
        f"GetParameter({param_name!r}) returned {param['Value']!r}, expected {_PARAM_VALUE!r}"
    )
    assert param["Type"] == "String", (
        f"GetParameter({param_name!r}) reports Type={param['Type']!r}, expected 'String'"
    )

    # ---- 3. THE HEADLINE: ListTagsForResource returns the parameter's own tags ------------
    tag_resp = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=param_name)
    param_tags = {t["Key"]: t["Value"] for t in tag_resp["TagList"]}
    assert param_tags.get("sim2real-role") == "tagged-parameter", (
        f"ListTagsForResource({param_name!r}) returned {param_tags!r}, expected a 'sim2real-role' "
        f"tag valued 'tagged-parameter'"
    )
    assert param_tags.get("sim2real") == CHECK, (
        f"ListTagsForResource({param_name!r}) returned {param_tags!r}, expected the stack-level "
        f"'sim2real' tag valued {CHECK!r}"
    )

    # ---- 4. cdk destroy, in-band, is the graded teardown -----------------------------------
    _cdk(ctx, work, ["destroy", "--force"], qualifier, stack, acct,
         timeout_s=_TEARDOWN_DEADLINE_S, expect_rc=0)

    # ---- 5. every resource is gone through its own API -------------------------------------
    secret_code, secret_message = _error(lambda: sm.get_secret_value(SecretId=secret_arn))
    assert (secret_code, secret_message) == (
        "ResourceNotFoundException", "Secrets Manager can't find the specified secret."), (
        f"after cdk destroy, GetSecretValue({secret_arn!r}) returned {secret_code!r}: "
        f"{secret_message!r}, expected an outright ResourceNotFoundException"
    )
    param_code, param_message = _error(lambda: ssm.get_parameter(Name=param_name))
    assert (param_code, param_message) == ("ParameterNotFound", ""), (
        f"after cdk destroy, GetParameter({param_name!r}) returned {param_code!r}: "
        f"{param_message!r}, expected an outright ParameterNotFound"
    )


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the on-disk CDK app to a temp workdir so cdk.out / cdk.context.json / out.json are
    never written next to the check."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdksmssm-"))
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
    acct = ctx.account
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
        time.sleep(2.0)
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
        if state.get("secret_arn"):
            try:
                ctx.client("secretsmanager").get_secret_value(SecretId=state["secret_arn"])
                remaining.append(f"secret {state['secret_arn']} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        if state.get("param_name"):
            try:
                ssm.get_parameter(Name=state["param_name"])
                remaining.append(f"parameter {state['param_name']} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ParameterNotFound":
                    raise
        if not remaining:
            break
        time.sleep(2.0)
    else:
        errors.append(f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")

    if errors:
        raise AssertionError(f"teardown failed to converge: {errors!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
