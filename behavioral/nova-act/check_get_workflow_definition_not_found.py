"""get-workflow-definition-not-found."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-workflow-definition-not-found"
GROUP = "error-semantics"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWorkflowDefinition on a name that was never created returns ResourceNotFoundException,
    while the same call for a definition that does exist succeeds (positive control)."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)

    # Positive control: an existing definition is readable.
    name = _wf_name(ctx, "nomisspc")
    nova.create_workflow_definition(name=name, clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=name)))
    got = nova.get_workflow_definition(workflowDefinitionName=name)
    assert got["status"] == "ACTIVE", f"positive control: expected ACTIVE, got {got.get('status')!r}"

    # A different, never-created name is rejected — not a blanket denial of the operation.
    missing_name = _wf_name(ctx, "nomiss")
    err = _client_error(lambda: nova.get_workflow_definition(workflowDefinitionName=missing_name))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    assert err.get("Message") == "Workflow definition not found", (
        f"expected the exact not-found message, got {err.get('Message')!r}"
    )


def _wf_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"n{kind}")
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:40]


def _client_token() -> str:
    return uuid.uuid4().hex + "-" + uuid.uuid4().hex


def _client_error(fn):
    """Call fn() and return its ClientError's ``Error`` dict (``Code``, ``Message``). An unexpected
    success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _silent(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
