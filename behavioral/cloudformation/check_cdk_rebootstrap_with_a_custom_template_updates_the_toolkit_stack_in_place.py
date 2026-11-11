"""cdk-rebootstrap-with-a-custom-template-updates-the-toolkit-stack-in-place."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-rebootstrap-with-a-custom-template-updates-the-toolkit-stack-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_BOOTSTRAP_TIMEOUT_S = 900.0
_TEARDOWN_DEADLINE_S = 420.0


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """Re-running `cdk bootstrap --template` with a modified template under the same qualifier and
    toolkit stack name UPDATEs that stack in place; a CreateChangeSet of the same template with a
    dangling `Ref` is refused first and leaves the stack unchanged.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-customizing.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    staging_bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    marker = ctx.unique_name("sim2real-bootstrap-marker-")
    state = {"bootstrapped": False}

    ctx.on_cleanup(lambda: _teardown_all(ctx, cfn, state, toolkit_stack, staging_bucket))

    # Set before the call: a bootstrap that fails part-way still leaves a stack and bucket.
    state["bootstrapped"] = True
    _bootstrap(ctx, qualifier, toolkit_stack, template_path=None)

    before = cfn.describe_stacks(StackName=toolkit_stack)["Stacks"][0]
    stack_id = before["StackId"]
    assert before["StackStatus"] == "CREATE_COMPLETE", (
        f"toolkit stack {toolkit_stack!r} settled at {before['StackStatus']!r} after the first "
        f"bootstrap, expected CREATE_COMPLETE"
    )
    before_outputs = {o["OutputKey"] for o in before.get("Outputs", [])}
    before_params = {p["ParameterKey"] for p in before.get("Parameters", [])}
    assert "BootstrapMarker" not in before_outputs, (
        f"toolkit stack {toolkit_stack!r} already carries a BootstrapMarker output before the "
        f"custom template is ever applied — the positive arm below would prove nothing"
    )
    assert "CustomMarkerParam" not in before_params, (
        f"toolkit stack {toolkit_stack!r} already carries a CustomMarkerParam parameter before "
        f"the custom template is ever applied — the positive arm below would prove nothing"
    )

    # NEGATIVE: a raw CreateChangeSet (not `cdk bootstrap`) of a template whose Outputs block
    # references a resource that does not exist is refused by CloudFormation itself.
    broken_template = _default_template(ctx)
    broken_template["Outputs"]["BrokenOutput"] = {
        "Value": {"Ref": "DoesNotExistParamOrResource"}
    }
    code, message = _error(lambda: cfn.create_change_set(
        StackName=toolkit_stack, TemplateBody=json.dumps(broken_template),
        ChangeSetName=ctx.unique_name("sim2real-cs-"), Capabilities=["CAPABILITY_NAMED_IAM"],
    ))
    assert (code, message) == (
        "ValidationError",
        "Unresolved resource dependencies [DoesNotExistParamOrResource] in the Outputs block of "
        "the template",
    ), f"CreateChangeSet with the broken template answered {(code, message)!r}"
    unchanged = cfn.describe_stacks(StackName=toolkit_stack)["Stacks"][0]
    unchanged_state = (unchanged["StackId"], unchanged["StackStatus"])
    assert unchanged_state == (stack_id, "CREATE_COMPLETE"), (
        f"toolkit stack {toolkit_stack!r} is {unchanged_state!r} after the rejected change set, "
        f"expected the SAME unchanged {(stack_id, 'CREATE_COMPLETE')!r}"
    )
    unchanged_outputs = {o["OutputKey"] for o in unchanged.get("Outputs", [])}
    assert "BrokenOutput" not in unchanged_outputs, (
        f"toolkit stack {toolkit_stack!r} Outputs {sorted(unchanged_outputs)!r} carry "
        f"BrokenOutput — a rejected change set must leave no trace"
    )

    # CONTROL: a validly modified template, through the real `cdk bootstrap --template` path,
    # still updates the same stack in place.
    custom_template_path = _custom_template(ctx, marker)
    _bootstrap(ctx, qualifier, toolkit_stack, template_path=custom_template_path)

    after = cfn.describe_stacks(StackName=toolkit_stack)["Stacks"][0]
    assert after["StackId"] == stack_id, (
        f"re-bootstrapping under the same qualifier and toolkit-stack-name produced StackId "
        f"{after['StackId']!r}, expected the SAME stack {stack_id!r} — this replaced the stack "
        f"instead of updating it in place"
    )
    assert after["StackStatus"] == "UPDATE_COMPLETE", (
        f"toolkit stack {toolkit_stack!r} settled at {after['StackStatus']!r} after the custom "
        f"re-bootstrap, expected UPDATE_COMPLETE"
    )

    after_outputs = {o["OutputKey"]: o["OutputValue"] for o in after.get("Outputs", [])}
    after_params = {p["ParameterKey"]: p["ParameterValue"] for p in after.get("Parameters", [])}
    assert after_outputs.get("BootstrapMarker") == marker, (
        f"toolkit stack {toolkit_stack!r} Outputs after the custom re-bootstrap were "
        f"{after_outputs!r}, expected BootstrapMarker={marker!r} from the custom template"
    )
    assert after_params.get("CustomMarkerParam") == marker, (
        f"toolkit stack {toolkit_stack!r} Parameters after the custom re-bootstrap were "
        f"{after_params!r}, expected CustomMarkerParam={marker!r} from the custom template"
    )
    # The pre-existing bucket (not a resource the custom template touched) must survive the
    # update: an in-place update, unlike a replacement, never recreates what it didn't change.
    unchanged_bucket = next(
        o["OutputValue"] for o in before["Outputs"] if o["OutputKey"] == "BucketName"
    )
    assert after_outputs.get("BucketName") == unchanged_bucket, (
        f"BucketName changed from {unchanged_bucket!r} to {after_outputs.get('BucketName')!r} "
        f"across the in-place update — the staging bucket the first bootstrap created must be "
        f"the SAME one the custom template still declares"
    )


def _default_template(ctx) -> dict:
    """The installed CLI's own bootstrap template, as a dict, fetched fresh each call."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdktplshow-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    result = subprocess.run(
        ["cdk", "bootstrap", "--show-template", "--json", "--ci", "--no-version-reporting",
         "--no-notices"],
        cwd=scratch, env=ctx.subprocess_env(), capture_output=True, text=True, timeout=180,
    )
    assert result.returncode == 0, (
        f"`cdk bootstrap --show-template` exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1000:]!r}"
    )
    # The CLI may write a notice line (e.g. an AI-agent banner) before the JSON object.
    text = result.stdout
    return json.loads(text[text.index("{"):text.rindex("}") + 1])


def _custom_template(ctx, marker: str) -> Path:
    """The default template, with one added Parameter and Output, written to a scratch file."""
    template = _default_template(ctx)
    template["Parameters"]["CustomMarkerParam"] = {"Type": "String", "Default": marker}
    template.setdefault("Outputs", {})["BootstrapMarker"] = {
        "Value": {"Ref": "CustomMarkerParam"}
    }
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdktplcustom-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    template_path = scratch / "custom-bootstrap-template.json"
    template_path.write_text(json.dumps(template))
    return template_path


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _bootstrap(ctx, qualifier: str, toolkit_stack: str, *, template_path: Path | None) -> None:
    """`cdk bootstrap` for one per-run qualifier; `template_path` set means a re-bootstrap."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--ci", "--no-version-reporting", "--no-notices", "--no-color",
        "--tags", f"sim2real={CHECK}",
    ]
    if template_path is not None:
        cmd += ["--template", str(template_path)]
    result = subprocess.run(cmd, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=_BOOTSTRAP_TIMEOUT_S)
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} (template={template_path}) exited "
        f"{result.returncode}, expected 0: {(result.stdout + result.stderr)[-1200:]!r}"
    )


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float) -> None:
    """Delete by name, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    try:
        cfn.describe_stacks(StackName=stack_name)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        if error.get("Code") == "ValidationError" and \
                error.get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "ValidationError" and \
                    error.get("Message") == f"Stack with id {stack_name} does not exist":
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach DELETE_COMPLETE within {timeout_s}s (last {last!r})"
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Purge every version and delete marker, then the bucket.

    The bootstrap StagingBucket has `DeletionPolicy: Retain`, so the toolkit delete leaves it.
    """
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


def _teardown_all(ctx, cfn, state: dict, toolkit_stack: str, staging_bucket: str) -> None:
    """Delete the staging bucket, then the toolkit stack."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps = []
    if state["bootstrapped"]:
        steps.append((f"staging bucket {staging_bucket}",
                     lambda: _empty_and_delete_bucket(ctx.client("s3"), staging_bucket)))
        steps.append((f"toolkit stack {toolkit_stack}", lambda: _delete_stack_and_wait(
            cfn, toolkit_stack, max(30.0, deadline - time.monotonic()))))
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
