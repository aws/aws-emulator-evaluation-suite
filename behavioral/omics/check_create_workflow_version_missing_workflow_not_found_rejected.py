"""create-workflow-version-missing-workflow-not-found-rejected."""
from __future__ import annotations

import io
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-workflow-version-missing-workflow-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["omics"]

_WDL_MAIN = """version 1.0

workflow sim2real_wfver {
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
    """CreateWorkflowVersion against a workflowId that doesn't exist is rejected with
    ResourceNotFoundException; the identical call against a real, active workflow succeeds."""
    omics = ctx.client("omics")
    fake_workflow_id = "9999999999"
    version_name = ctx.unique_name("sim2real-wfver-")

    expected_message = f"Workflow {fake_workflow_id} not found"
    code, message = _client_error(
        lambda: omics.create_workflow_version(
            workflowId=fake_workflow_id,
            versionName=version_name,
            definitionZip=_workflow_definition_zip(),
            requestId=ctx.unique_name("sim2real-wfverreq-"),
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no version was recorded, because the workflow itself still does not exist
    list_code, list_message = _client_error(lambda: omics.list_workflow_versions(workflowId=fake_workflow_id))
    assert list_code == "ResourceNotFoundException", (
        f"expected ListWorkflowVersions on a nonexistent workflow to reject with "
        f"ResourceNotFoundException, got {list_code!r}"
    )
    assert list_message == expected_message, f"expected message {expected_message!r}, got {list_message!r}"

    # positive control: the same call against a real, active workflow succeeds and reaches ACTIVE
    workflow_id = _create_active_workflow(ctx)
    created = omics.create_workflow_version(
        workflowId=workflow_id,
        versionName=version_name,
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfverreq2-"),
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: omics.delete_workflow_version(workflowId=workflow_id, versionName=version_name))

    status = created.get("status")
    deadline = time.monotonic() + 180
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = omics.get_workflow_version(workflowId=workflow_id, versionName=version_name)["status"]
    assert status == "ACTIVE", f"workflow version {version_name} ended in status {status!r}"


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


def _create_active_workflow(ctx) -> str:
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-wfverparent-")
    created = omics.create_workflow(
        name=name,
        engine="WDL",
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfreq-"),
        tags={"sim2real-check": CHECK},
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
