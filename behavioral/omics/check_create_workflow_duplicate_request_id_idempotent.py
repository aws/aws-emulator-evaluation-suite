"""create-workflow-duplicate-request-id-idempotent."""
from __future__ import annotations

import io
import zipfile

from behavioral_harness import tags

CHECK = "create-workflow-duplicate-request-id-idempotent"
GROUP = "state"
SERVICES = ["omics"]

_WDL_MAIN = """version 1.0

workflow sim2real_idem {
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkflow retried with the same requestId and identical params returns the same workflow, not a new one."""
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-wfidem-")
    request_id = ctx.unique_name("sim2real-wfidemreq-")
    definition = _workflow_definition_zip()

    first = omics.create_workflow(
        name=name, engine="WDL", definitionZip=definition, requestId=request_id,
        tags={"sim2real-check": CHECK},
    )
    workflow_id = first["id"]
    ctx.on_cleanup(lambda: omics.delete_workflow(id=workflow_id))

    second = omics.create_workflow(
        name=name, engine="WDL", definitionZip=definition, requestId=request_id,
        tags={"sim2real-check": CHECK},
    )

    assert second["id"] == workflow_id, (
        f"retry with identical requestId created a new workflow: {second['id']!r} != {workflow_id!r}"
    )
    assert second["uuid"] == first["uuid"], (
        f"retry with identical requestId returned a mismatched uuid: {second['uuid']!r} != {first['uuid']!r}"
    )

    listed_ids = [item["id"] for item in omics.list_workflows(name=name)["items"]]
    assert listed_ids.count(workflow_id) == 1, "duplicate requestId retry created more than one workflow"


def _workflow_definition_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.wdl", _WDL_MAIN)
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
