"""create-workflow-dryrun-no-mutation."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-workflow-dryrun-no-mutation"
GROUP = "state-machine"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWorkflow with dryRun=true validates the document but never persists a workflow."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-wf-")
    doc = (
        f"name: {name}\n"
        "description: dry run test workflow\n"
        "schemaVersion: 1.0\n"
        "steps:\n"
        "  - name: LaunchTestInstance\n"
        "    action: LaunchInstance\n"
        "    onFailure: Abort\n"
        "    inputs:\n"
        "      waitFor: \"ssmAgent\"\n"
        "  - name: TerminateTestInstance\n"
        "    action: TerminateInstance\n"
        "    onFailure: Continue\n"
        "    inputs:\n"
        "      instanceId.$: \"$.stepOutputs.LaunchTestInstance.instanceId\"\n"
    )

    code, msg = _error(
        lambda: ib.create_workflow(
            name=name,
            semanticVersion="1.0.0",
            type="TEST",
            data=doc,
            dryRun=True,
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "DryRunOperationException", f"expected DryRunOperationException, got {code!r}"
    expected = "Request would have succeeded, but dryRun flag is set."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    listed = ib.list_workflows()["workflowVersionList"]
    assert not any(w["name"] == name for w in listed), (
        f"dry-run workflow {name!r} must not be persisted, got names={[w['name'] for w in listed]}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
