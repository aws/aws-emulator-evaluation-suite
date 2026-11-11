"""create-workflow-duplicate-request-id-ignores-differing-params."""
from __future__ import annotations

import io
import zipfile

from behavioral_harness import tags

CHECK = "create-workflow-duplicate-request-id-ignores-differing-params"
GROUP = "state"
SERVICES = ["omics"]

_WDL_A = """version 1.0

workflow sim2real_a {
  call hello
}

task hello {
  command {
    echo "a"
  }
  output {
    String message = read_string(stdout())
  }
  runtime {
    docker: "public.ecr.aws/amazonlinux/amazonlinux:2"
  }
}
"""

_WDL_B = """version 1.0

workflow sim2real_b {
  call hello
}

task hello {
  command {
    echo "b, a totally different definition"
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
    """CreateWorkflow reusing a requestId with a different name and definition returns the original
    workflow's id and uuid and creates no second workflow, while a fresh requestId creates a new one."""
    omics = ctx.client("omics")
    request_id = ctx.unique_name("sim2real-wfconflictreq-")
    name = ctx.unique_name("sim2real-omics-wfconflict-")

    first = omics.create_workflow(
        name=name, engine="WDL", definitionZip=_zip(_WDL_A), requestId=request_id
    )
    first_id = first["id"]
    ctx.on_cleanup(lambda: omics.delete_workflow(id=first_id))

    retry = omics.create_workflow(
        name=ctx.unique_name("sim2real-omics-wfconflict-other-"),
        engine="WDL",
        definitionZip=_zip(_WDL_B),
        requestId=request_id,
    )

    # dedup solely by requestId: the retry returns the FIRST workflow's identity, ignoring
    # that name/definition differ, and does not create a second resource
    assert retry["id"] == first_id, f"retry with reused requestId created a new workflow: {retry['id']!r}"
    assert retry["uuid"] == first["uuid"], (
        f"retry uuid {retry['uuid']!r} != original uuid {first['uuid']!r}"
    )

    described = omics.get_workflow(id=first_id)
    assert described["name"] == name, "the original workflow's name must be unchanged by the retry"

    ids_with_name = [w["id"] for w in omics.list_workflows(name=name)["items"]]
    assert ids_with_name == [first_id], f"unexpected workflows for name {name!r}: {ids_with_name!r}"

    # positive control: a fresh requestId creates a genuinely independent workflow
    second_request_id = ctx.unique_name("sim2real-wfconflictreq2-")
    second = omics.create_workflow(
        name=ctx.unique_name("sim2real-omics-wfconflict2-"),
        engine="WDL",
        definitionZip=_zip(_WDL_B),
        requestId=second_request_id,
    )
    ctx.on_cleanup(lambda: omics.delete_workflow(id=second["id"]))
    assert second["id"] != first_id, (
        f"fresh requestId {second_request_id!r} incorrectly deduped onto {first_id!r}"
    )


def _zip(wdl_text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.wdl", wdl_text)
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

