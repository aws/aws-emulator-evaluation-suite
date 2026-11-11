"""workflow-creation-reaches-active."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags

CHECK = "workflow-creation-reaches-active"
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
    """CreateWorkflow with a valid WDL definitionZip starts CREATING and settles into ACTIVE."""
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-workflow-")

    created = omics.create_workflow(
        name=name,
        engine="WDL",
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfreq-"),
        tags={"sim2real": "true"},
    )
    workflow_id = created["id"]
    ctx.on_cleanup(lambda: omics.delete_workflow(id=workflow_id))

    status = created.get("status")
    deadline = time.monotonic() + 180
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = omics.get_workflow(id=workflow_id)["status"]

    assert status == "ACTIVE", f"workflow {workflow_id} ended in status {status!r}"

    described = omics.get_workflow(id=workflow_id)
    assert described["name"] == name, f"expected name {name!r}, got {described['name']!r}"
    assert described["status"] == "ACTIVE", f"expected status ACTIVE, got {described['status']!r}"
    assert described["engine"] == "WDL", f"expected engine WDL, got {described['engine']!r}"


def _workflow_definition_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.wdl", _WDL_MAIN)
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
