"""delete-workflow-with-version-conflict-rejected."""
from __future__ import annotations

import io
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-workflow-with-version-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["omics"]

# DeleteWorkflow while a version still exists is rejected with
# ValidationException (not ConflictException as the API's error list might suggest).

_WDL_MAIN = """version 1.0

workflow sim2real_conflict {
  call hello
}

task hello {
  command {
    echo "hello from sim2real"
  }
  output {
    String message = read_string(stdout())
  }
  runtime {
    docker: "public.ecr.aws/amazonlinux/amazonlinux:2"
  }
}
"""


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkflow is rejected while a workflow version still exists; it succeeds once the version
    is gone, and the deleted workflow is then unreachable (GetWorkflow 404s, and a mutation against
    it fails the same way)."""
    omics = ctx.client("omics")
    workflow_id = _create_active_workflow(ctx)
    version_name = _create_active_workflow_version(ctx, workflow_id)

    code, message = _client_error(lambda: omics.delete_workflow(id=workflow_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "Cannot delete the requested workflow, as it has one or more versions. "
        "Delete the versions and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the workflow (and its version) are untouched
    still_there = omics.get_workflow(id=workflow_id)
    assert still_there["status"] == "ACTIVE", (
        f"workflow {workflow_id} status changed to {still_there['status']!r} after a rejected DeleteWorkflow"
    )
    still_version = omics.get_workflow_version(workflowId=workflow_id, versionName=version_name)
    assert still_version["status"] == "ACTIVE", (
        f"workflow version {version_name} status changed to {still_version['status']!r} after a rejected DeleteWorkflow"
    )

    # positive control: removing the blocking version first lets DeleteWorkflow succeed
    omics.delete_workflow_version(workflowId=workflow_id, versionName=version_name)
    _wait_workflow_version_gone(ctx, workflow_id, version_name)
    omics.delete_workflow(id=workflow_id)

    # deletes prove gone and unusable: an independent read 404s, and so does a mutation on the dead id
    _wait_workflow_gone(ctx, workflow_id)
    version_code, version_message = _client_error(
        lambda: omics.delete_workflow_version(workflowId=workflow_id, versionName=version_name)
    )
    assert version_code == "ResourceNotFoundException", (
        f"DeleteWorkflowVersion against deleted workflow {workflow_id} returned {version_code!r}, "
        "expected ResourceNotFoundException"
    )
    expected_gone = f"Workflow {workflow_id} version {version_name} not found"
    assert version_message == expected_gone, f"expected message {expected_gone!r}, got {version_message!r}"


def _workflow_definition_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.wdl", _WDL_MAIN)
    return buf.getvalue()


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_active_workflow(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-workflow-")
    created = omics.create_workflow(
        name=name,
        engine="WDL",
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfreq-"),
        tags={"sim2real:managed": "true"},
    )
    workflow_id = created["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_workflow(ctx, workflow_id))

    status = created.get("status")
    deadline = time.monotonic() + 180
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = omics.get_workflow(id=workflow_id)["status"]
    if status != "ACTIVE":
        raise AssertionError(f"prerequisite workflow {workflow_id} ended in status {status!r}")
    return workflow_id


def _create_active_workflow_version(ctx, workflow_id: str) -> str:
    omics = ctx.client("omics")
    version_name = ctx.unique_name("sim2real-wfver-")
    created = omics.create_workflow_version(
        workflowId=workflow_id,
        versionName=version_name,
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfverreq-"),
        tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _best_effort_delete_workflow_version(ctx, workflow_id, version_name))

    status = created.get("status")
    deadline = time.monotonic() + 180
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = omics.get_workflow_version(workflowId=workflow_id, versionName=version_name)["status"]
    if status != "ACTIVE":
        raise AssertionError(f"prerequisite workflow version {version_name} ended in status {status!r}")
    return version_name


def _wait_workflow_version_gone(ctx, workflow_id: str, version_name: str) -> None:
    omics = ctx.client("omics")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        names = [v["versionName"] for v in omics.list_workflow_versions(workflowId=workflow_id)["items"]]
        if version_name not in names:
            return
        time.sleep(2)
    raise AssertionError(f"workflow version {version_name} was not removed after DeleteWorkflowVersion")


def _wait_workflow_gone(ctx, workflow_id: str) -> None:
    omics = ctx.client("omics")
    deadline = time.monotonic() + 60
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = omics.get_workflow(id=workflow_id)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(
        f"workflow {workflow_id} was not confirmed deleted within 60s of DeleteWorkflow "
        f"(last get_workflow status: {last_status!r})"
    )


def _best_effort_delete_workflow(ctx, workflow_id: str) -> None:
    try:
        ctx.client("omics").delete_workflow(id=workflow_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete_workflow_version(ctx, workflow_id: str, version_name: str) -> None:
    try:
        ctx.client("omics").delete_workflow_version(workflowId=workflow_id, versionName=version_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
