"""cdk-migrate-from-stack-deploy-updates-in-place-without-replacing-the-queue."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-migrate-from-stack-deploy-updates-in-place-without-replacing-the-queue"
GROUP = "deploy"
SERVICES = ["cloudformation", "sqs"]

_STACK_TIMEOUT_S = 300.0
_MIGRATE_TIMEOUT_S = 300.0
_SYNTH_TIMEOUT_S = 180.0


@tags("axis:happy-path", "cap:c2", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk migrate --from-stack` generates an app whose template, deployed back onto the same
    stack, updates the queue in place: the physical id is unchanged and the property edit
    that forced the update actually took effect.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/migrate.html
    Reference: https://docs.aws.amazon.com/cdk/v2/guide/ref-cli-cdk-migrate.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    stack = ctx.unique_name("sim2real-cdkmig-")
    queue_name = ctx.unique_name("sim2real-cdkmig-q-")

    # ---- 0. a plain CloudFormation stack, created without CDK -------------------------------
    template = json.dumps({
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_name, "VisibilityTimeout": 30},
            }
        }
    })
    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": "cdk-migrate"}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))
    status = _wait_stack_terminal(cfn, stack_id, timeout_s=_STACK_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"baseline stack {stack!r} reached {status!r}, expected CREATE_COMPLETE"
    )

    before_url = _physical_id(cfn, stack_id, "Queue")
    before_vt = _visibility_timeout(sqs, before_url)
    assert before_vt == "30", (
        f"baseline queue {before_url!r} reports VisibilityTimeout {before_vt!r}, expected '30'"
    )

    # ---- 1. cdk migrate --from-stack: generate a CDK app from the deployed stack ------------
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkmig-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    rc, out = _cdk(ctx, work, [
        "migrate", "--from-stack", "--stack-name", stack, "--language", "python",
        "--output-path", str(work),
    ], timeout_s=_MIGRATE_TIMEOUT_S)
    assert rc == 0, f"`cdk migrate --from-stack` exited {rc}; output tail: {out[-1500:]!r}"

    app_dir = work / stack
    assert app_dir.is_dir(), (
        f"`cdk migrate` reported success but {app_dir} does not exist; output tail: "
        f"{out[-1500:]!r}"
    )
    # The generated project's own virtualenv is never used — this check runs the app with its
    # own interpreter (_point_app_at_this_interpreter) — so drop it before it can shadow the
    # search below with its own vendored `_stack.py` files.
    shutil.rmtree(app_dir / ".venv", ignore_errors=True)
    stack_file = _find_stack_file(app_dir)
    source = stack_file.read_text()
    assert "CfnQueue" in source and "'Queue'" in source, (
        f"the migrated app's stack file does not declare a CfnQueue construct named 'Queue': "
        f"{source!r}"
    )

    # ---- 2. edit ONE mutable property, so the round trip is a real update, not a no-op ------
    edited = source.replace("visibility_timeout = 30,", "visibility_timeout = 61,")
    assert edited != source, (
        f"could not find 'visibility_timeout = 30,' to edit in the migrated stack file: "
        f"{source!r}"
    )
    stack_file.write_text(edited)
    _point_app_at_this_interpreter(app_dir)

    # ---- 3. synth the migrated+edited app, then deploy its template directly via CloudFormation
    # (not `cdk deploy`): the app is asset-free, so no bootstrap is needed for this round trip,
    # and the synthesized template's BootstrapVersion SSM parameter has no resource referencing
    # it, so it is dropped rather than requiring a bootstrap this check never performed.
    rc, synth_out = _cdk(ctx, app_dir, ["synth", stack, "-j"], timeout_s=_SYNTH_TIMEOUT_S)
    assert rc == 0, (
        f"`cdk synth` on the migrated app exited {rc}; output tail: {synth_out[-1500:]!r}"
    )
    migrated_template = _extract_json(synth_out)
    migrated_template.pop("Parameters", None)
    migrated_resource = migrated_template.get("Resources", {}).get("Queue", {})
    assert migrated_resource.get("Properties", {}).get("VisibilityTimeout") == 61, (
        f"the synthesized template's Queue does not carry VisibilityTimeout=61: "
        f"{migrated_resource!r}"
    )

    cfn.update_stack(StackName=stack, TemplateBody=json.dumps(migrated_template))
    status = _wait_stack_terminal(cfn, stack_id, timeout_s=_STACK_TIMEOUT_S)
    assert status == "UPDATE_COMPLETE", (
        f"deploying the migrated app's template onto {stack!r} reached {status!r}, expected "
        f"UPDATE_COMPLETE"
    )

    # ---- TERMINAL READ: same physical queue, with the edited property now in effect ---------
    after_url = _physical_id(cfn, stack_id, "Queue")
    assert after_url == before_url, (
        f"the queue's physical id changed from {before_url!r} to {after_url!r} — cdk migrate's "
        f"generated app replaced the resource instead of updating it in place"
    )
    after_vt = _visibility_timeout(sqs, after_url)
    assert after_vt == "61", (
        f"queue {after_url!r} reports VisibilityTimeout {after_vt!r} after the deploy, expected "
        f"'61' — the migrated app's edited property did not take effect"
    )


def _cdk(ctx, work: Path, args: list[str], *, timeout_s: float) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning ``(returncode, stdout+stderr)``."""
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    return result.returncode, result.stdout + result.stderr


def _extract_json(cdk_output: str) -> dict:
    """The JSON object `cdk synth -j` printed, skipping its leading banner line and any trailing
    stderr noise (a node version notice) that follows the object on the same combined stream."""
    start = cdk_output.index("{")
    obj, _ = json.JSONDecoder().raw_decode(cdk_output, start)
    return obj


def _find_stack_file(app_dir: Path) -> Path:
    """The generated app's single `*_stack.py`, outside its `tests/` directory."""
    candidates = [p for p in app_dir.rglob("*_stack.py") if "tests" not in p.parts]
    assert len(candidates) == 1, (
        f"expected exactly one *_stack.py under {app_dir}, found {candidates!r}"
    )
    return candidates[0]


def _point_app_at_this_interpreter(app_dir: Path) -> None:
    """Rewrite the migrated app's `cdk.json` to run with this process's own Python, so the
    CDK CLI never needs the generated project's separate virtualenv."""
    cdk_json = app_dir / "cdk.json"
    config = json.loads(cdk_json.read_text())
    config["app"] = f"{sys.executable} app.py"
    cdk_json.write_text(json.dumps(config))


_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _wait_stack_terminal(cfn, stack_id: str, *, timeout_s: float, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_id} did not reach a terminal status within {timeout_s}s (last={status})"
    )


def _delete_stack_and_wait(cfn, stack_id: str, *, timeout_s: float = 300.0) -> None:
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_id)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_id!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_id!r} did not reach DELETE_COMPLETE within {timeout_s}s (last {last!r})"
    )


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resources(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResources"
    ][0]["PhysicalResourceId"]


def _visibility_timeout(sqs, queue_url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
