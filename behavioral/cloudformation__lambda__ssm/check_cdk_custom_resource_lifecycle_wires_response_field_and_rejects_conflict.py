"""cdk-custom-resource-lifecycle-wires-response-field-and-rejects-conflict."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-custom-resource-lifecycle-wires-response-field-and-rejects-conflict"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "ssm"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_custom_resource_ssm"
# --ci keeps the CLI off a TTY; --no-notices / --no-version-reporting keep it off the network.
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices")

_FAILURE_PREFIX = "Received response status [FAILED] from custom resource. Message returned: "
_CONFLICT_MESSAGE = (
    "The parameter already exists. To overwrite this value, set the overwrite option in the "
    "request to true."
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """A Custom::AWS resource's onCreate/onUpdate/onDelete each issue the declared SSM call, its
    response field feeds a sibling resource's property, and a call AWS itself refuses leaves the
    target parameter untouched until the one conflicting thing is removed.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    ssm = ctx.client("ssm")
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    staging = f"cdk-{qualifier}-assets-{account}-{ctx.region}"

    work = _stage_app(ctx, _APP)
    lifecycle_stack = ctx.unique_name("sim2real-cruow-")
    conflict_stack = ctx.unique_name("sim2real-cruow-cf-")
    param_name = ctx.unique_name("sim2real-cruow-param-")
    mirror_name = ctx.unique_name("sim2real-cruow-mirror-")
    conflict_param = ctx.unique_name("sim2real-cruow-conflict-")
    function_names: list[str] = []

    base_env = {"QUALIFIER": qualifier, "CDK_DEFAULT_ACCOUNT": account, "CDK_DEFAULT_REGION": ctx.region}

    try:
        _bootstrap(ctx, account, qualifier, toolkit)

        # ---- 1. CREATE: onCreate issues the call; its response field feeds the sibling -------
        value1 = ctx.unique_name("v1-")
        try:
            _cdk(ctx, work, ["deploy", lifecycle_stack, "--require-approval", "never"],
                 {**base_env, "SCENARIO": "lifecycle", "STACK_NAME": lifecycle_stack,
                  "PARAM_NAME": param_name, "PARAM_VALUE": value1, "MIRROR_NAME": mirror_name},
                 timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        finally:
            _record_functions(cfn, lifecycle_stack, function_names)
        provider = _singleton_function_name(cfn, lifecycle_stack)

        created = ssm.get_parameter(Name=param_name)["Parameter"]
        assert created["Value"] == value1, (
            f"onCreate's putParameter call did not land: GetParameter on {param_name!r} returned "
            f"value {created['Value']!r}, expected {value1!r}"
        )
        assert created["Version"] == 1, (
            f"a freshly created parameter {param_name!r} is at version {created['Version']!r}, "
            f"expected 1"
        )
        mirror1 = ssm.get_parameter(Name=mirror_name)["Parameter"]["Value"]
        assert mirror1 == "1", (
            f"the sibling parameter {mirror_name!r} holds {mirror1!r}, expected '1' — "
            f"get_response_field('Version') did not reach the sibling's Value property"
        )
        state1 = lam.get_function(FunctionName=provider)["Configuration"]["State"]
        assert state1 == "Active", (
            f"the provider Lambda {provider!r} that ran onCreate is in state {state1!r}, "
            f"expected 'Active'"
        )

        # ---- 2. UPDATE: a property change makes onUpdate issue a NEW call ---------------------
        value2 = ctx.unique_name("v2-")
        try:
            _cdk(ctx, work, ["deploy", lifecycle_stack, "--require-approval", "never"],
                 {**base_env, "SCENARIO": "lifecycle", "STACK_NAME": lifecycle_stack,
                  "PARAM_NAME": param_name, "PARAM_VALUE": value2, "MIRROR_NAME": mirror_name},
                 timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        finally:
            _record_functions(cfn, lifecycle_stack, function_names)
        updated = ssm.get_parameter(Name=param_name)["Parameter"]
        assert updated["Value"] == value2, (
            f"onUpdate did not issue the new call: GetParameter on {param_name!r} returned "
            f"{updated['Value']!r}, expected {value2!r} after the Value property changed"
        )
        assert updated["Version"] == 2, (
            f"after onUpdate, {param_name!r} is at version {updated['Version']!r}, expected 2"
        )
        mirror2 = ssm.get_parameter(Name=mirror_name)["Parameter"]["Value"]
        assert mirror2 == "2", (
            f"the sibling parameter {mirror_name!r} holds {mirror2!r}, expected '2' after "
            f"onUpdate — it did not pick up the new response field"
        )

        # ---- 3. DELETE: onDelete issues the call when the stack is destroyed ------------------
        _delete_stack_and_wait(ctx, lifecycle_stack)
        absent = _error(lambda: ssm.get_parameter(Name=param_name))
        assert absent == ("ParameterNotFound", ""), (
            f"onDelete did not remove {param_name!r}: GetParameter raised {absent!r}, expected "
            f"ParameterNotFound with no message"
        )
        mirror_absent = _error(lambda: ssm.get_parameter(Name=mirror_name))
        assert mirror_absent[0] == "ParameterNotFound", (
            f"the sibling parameter {mirror_name!r} survived stack deletion: {mirror_absent!r}"
        )

        # ---- 4. REJECTED: AWS itself refuses onCreate; the parameter is left untouched --------
        original_value = ctx.unique_name("orig-")
        ssm.put_parameter(Name=conflict_param, Value=original_value, Type="String")
        new_value = ctx.unique_name("new-")
        try:
            rc, out = _cdk(ctx, work, ["deploy", conflict_stack, "--require-approval", "never"],
                           {**base_env, "SCENARIO": "conflict", "STACK_NAME": conflict_stack,
                            "CONFLICT_PARAM_NAME": conflict_param, "CONFLICT_VALUE": new_value},
                           timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
        finally:
            _record_functions(cfn, conflict_stack, function_names)
        assert rc != 0, (
            f"`cdk deploy` exited 0 deploying a Custom::AWS putParameter with no Overwrite flag "
            f"against the pre-existing parameter {conflict_param!r}; AWS must refuse it. Output "
            f"tail: {out[-800:]!r}"
        )
        status = _wait_terminal_status(cfn, conflict_stack)
        assert status == "ROLLBACK_COMPLETE", (
            f"stack {conflict_stack!r} reached {status!r}, expected ROLLBACK_COMPLETE after the "
            f"refused onCreate call"
        )
        _singleton_function_name(cfn, conflict_stack)
        reason = _custom_resource_failure_reason(cfn, conflict_stack)
        assert reason.startswith(_FAILURE_PREFIX), (
            f"the Custom::AWS failure reason {reason!r} does not carry the custom-resource "
            f"envelope prefix {_FAILURE_PREFIX!r}"
        )
        body = reason[len(_FAILURE_PREFIX):]
        assert body.startswith(_CONFLICT_MESSAGE + " (RequestId: ") and body.endswith(")"), (
            f"the Custom::AWS failure reason's message was {body!r}, expected it to wrap SSM's "
            f"exact ParameterAlreadyExists message {_CONFLICT_MESSAGE!r} followed by a trailing "
            f"RequestId"
        )
        request_id = body[len(_CONFLICT_MESSAGE) + len(" (RequestId: "):-1]
        assert len(request_id) == 36 and request_id.count("-") == 4, (
            f"the trailing RequestId {request_id!r} is not shaped like a UUID"
        )
        untouched = ssm.get_parameter(Name=conflict_param)["Parameter"]
        assert untouched["Value"] == original_value and untouched["Version"] == 1, (
            f"the refused call changed {conflict_param!r} to {untouched!r}; a refusal must leave "
            f"the parameter exactly as it was"
        )

        # ---- 5. CONTROL: remove the one broken thing, the identical call now succeeds --------
        _delete_stack_and_wait(ctx, conflict_stack)
        ssm.delete_parameter(Name=conflict_param)
        try:
            _cdk(ctx, work, ["deploy", conflict_stack, "--require-approval", "never"],
                 {**base_env, "SCENARIO": "conflict", "STACK_NAME": conflict_stack,
                  "CONFLICT_PARAM_NAME": conflict_param, "CONFLICT_VALUE": new_value},
                 timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        finally:
            _record_functions(cfn, conflict_stack, function_names)
        _singleton_function_name(cfn, conflict_stack)
        landed = ssm.get_parameter(Name=conflict_param)["Parameter"]
        assert landed["Value"] == new_value, (
            f"control: once the pre-existing parameter was removed, the identical onCreate call "
            f"produced {landed['Value']!r}, expected {new_value!r} — the earlier refusal was not "
            f"caused by the conflicting parameter after all"
        )
    finally:
        _teardown(ctx, [lifecycle_stack, conflict_stack], staging, toolkit, qualifier, account,
                  [param_name, mirror_name, conflict_param], function_names)


def _stack_missing(exc: ClientError) -> bool:
    """True only for CloudFormation's own not-found refusal for a stack name."""
    error = exc.response["Error"]
    return error["Code"] == "ValidationError" and "does not exist" in str(error.get("Message", ""))


def _record_functions(cfn, stack: str, function_names: list[str]) -> None:
    """Add the stack's Lambda functions to *function_names*, so teardown reaps their log groups."""
    try:
        resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    except ClientError as exc:
        if _stack_missing(exc):
            return
        raise
    for resource in resources:
        name = resource.get("PhysicalResourceId")
        if resource["ResourceType"] != "AWS::Lambda::Function" or not name:
            continue
        if name not in function_names:
            function_names.append(name)


def _singleton_function_name(cfn, stack: str) -> str:
    """The physical name of the stack's one AwsCustomResource provider Lambda."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    fns = [r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::Lambda::Function"]
    assert len(fns) == 1, f"stack {stack!r} has {len(fns)} Lambda functions, expected exactly 1"
    return fns[0]


def _custom_resource_failure_reason(cfn, stack: str) -> str:
    """The `ResourceStatusReason` of the stack's one CREATE_FAILED Custom::AWS event."""
    reasons = [
        str(event["ResourceStatusReason"])
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack)
        for event in page["StackEvents"]
        if event["ResourceType"] == "Custom::AWS" and event["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, (
        f"stack {stack!r} has {len(reasons)} CREATE_FAILED Custom::AWS events, expected exactly 1"
    )
    return reasons[0]


def _wait_terminal_status(cfn, stack: str, *, timeout_s: float = 120.0) -> str:
    """Poll `DescribeStacks` to a terminal (non `_IN_PROGRESS`) status."""
    deadline = time.monotonic() + timeout_s
    status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    while status.endswith("_IN_PROGRESS") and time.monotonic() < deadline:
        time.sleep(5.0)
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    return str(status)


def _error(fn) -> tuple[str, str]:
    """The AWS `(code, message)` a call raises; raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError("call succeeded but was expected to be refused")


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present={(source / 'app.py').is_file()}, "
        f"cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _bootstrap(ctx, account: str, qualifier: str, toolkit: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cruow-boot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    command = [
        "cdk", "bootstrap", f"aws://{account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        # The staging bucket's name does not carry the sim2real prefix, so tag it via the stack.
        "--tags", f"sim2real={CHECK}",
        *_CDK_FLAGS,
    ]
    result = subprocess.run(command, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0. "
        f"Output tail: {(result.stdout + result.stderr)[-1000:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], extra_env: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env.update(extra_env)
    cmd = ["cdk", *args, *_CDK_FLAGS, "--no-color"]
    result = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                            timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 300.0) -> None:
    """Delete, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """Purge every version and delete marker, then the bucket."""
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


def _delete_parameter(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
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
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; {absent} "
                    f"clean reads"
                )
            time.sleep(interval_s)


def _bootstrap_remnants(ctx, staging: str, toolkit: str, qualifier: str, account: str) -> list[str]:
    """What bootstrap left behind, by exact name. Never a prefix sweep across the account."""
    remaining: list[str] = []
    try:
        status = ctx.client("cloudformation").describe_stacks(StackName=toolkit)["Stacks"][0][
            "StackStatus"]
        if status != "DELETE_COMPLETE":
            remaining.append(f"toolkit stack {toolkit} in {status}")
    except ClientError as exc:
        if not _stack_missing(exc):
            raise
    try:
        ctx.client("s3").head_bucket(Bucket=staging)
        remaining.append(f"staging bucket {staging}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise
    try:
        ctx.client("ssm").get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
        remaining.append("bootstrap version parameter")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise
    repository = f"cdk-{qualifier}-container-assets-{account}-{ctx.region}"
    try:
        ctx.client("ecr").describe_repositories(repositoryNames=[repository])
        remaining.append(f"container assets repository {repository}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise
    iam = ctx.client("iam")
    roles = [role["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for role in page["Roles"] if role["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        remaining.append(f"bootstrap roles {roles!r}")
    return remaining


def _teardown(ctx, stacks: list[str], staging: str, toolkit: str, qualifier: str, account: str,
             parameters: list[str], function_names: list[str]) -> None:
    """Delete every app stack, its parameters and log groups, then bootstrap itself.

    Inline rather than `ctx.on_cleanup`, whose 60s cap cannot cover a bootstrap teardown. Every
    step runs; each failure is collected and the teardown raises on them at the end.
    """
    ssm = ctx.client("ssm")
    logs = ctx.client("logs")
    steps = [(f"app stack {stack}", lambda stack=stack: _delete_stack_and_wait(ctx, stack))
             for stack in stacks]
    steps += [(f"log group of {fn}", lambda fn=fn: _reap_log_group(logs, f"/aws/lambda/{fn}"))
              for fn in function_names]
    steps += [(f"parameter {name}", lambda name=name: _delete_parameter(ssm, name))
              for name in parameters]
    steps += [(f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
              (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit))]
    errors: list[str] = []
    for label, step in steps:
        if label == f"staging bucket {staging}" and any(e.startswith("app stack ") for e in errors):
            # The app stacks delete as the toolkit's exec role: deleting the toolkit strands them.
            raise AssertionError(f"toolkit stack {toolkit} and staging bucket kept: "
                                 + "; ".join(errors))
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown must report, never mask the verdict
            errors.append(f"{label}: {exc!r}")
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining = _bootstrap_remnants(ctx, staging, toolkit, qualifier, account)
    while remaining and time.monotonic() < deadline:
        time.sleep(5.0)
        remaining = _bootstrap_remnants(ctx, staging, toolkit, qualifier, account)
    if remaining:
        errors.append(f"bootstrap remnants still present after {_TEARDOWN_DEADLINE_S}s: "
                      f"{remaining!r}")
    if errors:
        raise AssertionError("teardown left residue: " + "; ".join(errors))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
