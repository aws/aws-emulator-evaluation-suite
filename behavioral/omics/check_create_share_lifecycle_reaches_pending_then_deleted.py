"""create-share-lifecycle-reaches-pending-then-deleted."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags

CHECK = "create-share-lifecycle-reaches-pending-then-deleted"
GROUP = "state"
SERVICES = ["omics"]

_WDL_MAIN = """version 1.0

workflow sim2real_share {
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
    """CreateShare offers a resource to an external account (PENDING) and DeleteShare tears it down (DELETED)."""
    omics = ctx.client("omics")
    workflow_id, workflow_arn = _create_active_workflow(ctx)

    created = omics.create_share(
        resourceArn=workflow_arn,
        principalSubscriber="111122223333",
        shareName=ctx.unique_name("sim2real-share-"),
    )
    share_id = created["shareId"]
    ctx.on_cleanup(lambda: _delete_share_ignore_missing(omics, share_id))
    assert created["status"] == "PENDING", f"expected a freshly-created share to be PENDING, got {created['status']!r}"

    from botocore.exceptions import ClientError as _ClientError

    described = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            described = omics.get_share(shareId=share_id)["share"]
            break
        except _ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                time.sleep(2)
                continue
            raise
    assert described is not None, f"share {share_id} never became describable after creation"
    assert described["status"] == "PENDING", f"expected the independent get_share read to see PENDING, got {described['status']!r}"
    assert described["resourceArn"] == workflow_arn, (
        f"expected get_share to echo the shared resource {workflow_arn!r}, got {described['resourceArn']!r}"
    )

    omics.delete_share(shareId=share_id)

    final_status = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            final_status = omics.get_share(shareId=share_id)["share"]["status"]
        except _ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                # once fully deleted, the share is removed entirely rather than
                # lingering in a DELETED status
                final_status = "DELETED"
                break
            raise
        if final_status == "DELETED":
            break
        time.sleep(2)

    assert final_status == "DELETED", (
        f"share {share_id} did not reach DELETED within the deadline (last observed {final_status!r})"
    )

    try:
        omics.delete_share(shareId=share_id)
    except _ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected a second delete_share on the already-deleted share {share_id} to fail with "
            f"ResourceNotFoundException, got {exc.response['Error']['Code']!r}"
        )
        message = exc.response["Error"]["Message"]
        assert message == "Requested share not found", f"unexpected not-found message: {message!r}"
    else:
        raise AssertionError(f"expected delete_share on the already-deleted share {share_id} to fail, but it succeeded")


def _delete_share_ignore_missing(omics, share_id):
    from botocore.exceptions import ClientError

    try:
        omics.delete_share(shareId=share_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _workflow_definition_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.wdl", _WDL_MAIN)
    return buf.getvalue()


def _create_active_workflow(ctx):
    omics = ctx.client("omics")
    name = ctx.unique_name("sim2real-omics-shareworkflow-")
    created = omics.create_workflow(
        name=name,
        engine="WDL",
        definitionZip=_workflow_definition_zip(),
        requestId=ctx.unique_name("sim2real-wfreq-"),
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
    return workflow_id, created["arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
