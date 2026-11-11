"""create-workflow-get-roundtrip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-workflow-get-roundtrip"
GROUP = "control-plane"
SERVICES = ["imagebuilder"]

_WORKFLOW_DATA = """
name: sim2real-test-workflow
description: minimal test workflow
schemaVersion: 1.0

steps:
  - name: PauseStep
    action: WaitForAction
    onFailure: Abort
    timeoutSeconds: 60
""".strip()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkflow persists the type/version/document exactly as submitted."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-workflow-")
    resp = ib.create_workflow(
        name=name,
        semanticVersion="1.0.0",
        type="TEST",
        data=_WORKFLOW_DATA,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )
    arn = resp["workflowBuildVersionArn"]
    ctx.on_cleanup(lambda: _delete_if_present(ib, arn))

    got = ib.get_workflow(workflowBuildVersionArn=arn)["workflow"]
    assert got["arn"] == arn, f"expected arn {arn!r}, got {got['arn']!r}"
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["type"] == "TEST", f"expected type 'TEST', got {got['type']!r}"
    assert got["version"] == "1.0.0", f"expected version '1.0.0', got {got['version']!r}"
    assert got["data"] == _WORKFLOW_DATA, (
        f"expected data to round-trip exactly, got {got['data']!r}"
    )

    ib.delete_workflow(workflowBuildVersionArn=arn)
    code, msg = _error(lambda: ib.get_workflow(workflowBuildVersionArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code!r}"
    )
    expected = f"The following required resource 'Workflow' cannot be found: '{arn}'."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(ib, arn: str) -> None:
    try:
        ib.delete_workflow(workflowBuildVersionArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
