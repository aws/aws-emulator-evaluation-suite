"""workflow-version-creation-reaches-active."""
from __future__ import annotations

import io
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workflow-version-creation-reaches-active"
GROUP = "state"
SERVICES = ["omics"]

_WDL_MAIN = """version 1.0

workflow sim2real_smoke {
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkflowVersion on an existing workflow starts CREATING and settles into ACTIVE."""
    omics = ctx.client("omics")
    workflow_id = _create_workflow(ctx)

    version_name = ctx.unique_name("sim2real-wfver-")
    created = omics.create_workflow_version(
        workflowId=workflow_id,
        versionName=version_name,
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfverreq-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(
        lambda: _best_effort_delete_workflow_version(ctx, workflow_id, version_name)
    )

    status = created.get("status")
    deadline = time.monotonic() + 180
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = omics.get_workflow_version(workflowId=workflow_id, versionName=version_name)["status"]

    assert status == "ACTIVE", f"workflow version {version_name} ended in status {status!r}"

    described = omics.get_workflow_version(workflowId=workflow_id, versionName=version_name)
    assert described["workflowId"] == workflow_id, (
        f"expected workflowId {workflow_id!r}, got {described['workflowId']!r}"
    )
    assert described["versionName"] == version_name, (
        f"expected versionName {version_name!r}, got {described['versionName']!r}"
    )
    assert described["status"] == "ACTIVE", f"expected status ACTIVE, got {described['status']!r}"

    # The delete this check already performs on cleanup is a free negative once asserted here —
    # gone via an independent read, and a repeat delete on the dead id also refuses.
    omics.delete_workflow_version(workflowId=workflow_id, versionName=version_name)
    gone_code, gone_message = _client_error(
        lambda: omics.get_workflow_version(workflowId=workflow_id, versionName=version_name)
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted version, got {gone_code!r}"
    )
    expected_gone = f"Workflow {workflow_id} with version name {version_name} not found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"
    redelete_code, redelete_message = _client_error(
        lambda: omics.delete_workflow_version(workflowId=workflow_id, versionName=version_name)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted version, got {redelete_code!r}"
    )
    expected_redelete = f"Workflow {workflow_id} version {version_name} not found"
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
    )


def _workflow_definition_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.wdl", _WDL_MAIN)
    return buf.getvalue()


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete_workflow_version(ctx, workflow_id: str, version_name: str) -> None:
    try:
        ctx.client("omics").delete_workflow_version(workflowId=workflow_id, versionName=version_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_workflow(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-workflow-")
    created = omics.create_workflow(
        name=name,
        engine="WDL",
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfreq-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    workflow_id = created["id"]
    ctx.on_cleanup(lambda: omics.delete_workflow(id=workflow_id))

    status = created.get("status")
    deadline = time.monotonic() + 180
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = omics.get_workflow(id=workflow_id)["status"]
    if status != "ACTIVE":
        raise AssertionError(f"prerequisite workflow {workflow_id} ended in status {status!r}")
    return workflow_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
