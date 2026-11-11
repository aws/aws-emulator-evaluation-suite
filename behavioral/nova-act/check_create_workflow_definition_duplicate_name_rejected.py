"""create-workflow-definition-duplicate-name-rejected."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workflow-definition-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWorkflowDefinition with an existing name and a fresh clientToken fails with
    ConflictException "Workflow definition already exists" and leaves the original description; an
    unused name is created ACTIVE and reads back ACTIVE."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    name = _wf_name(ctx, "wfdup")
    nova.create_workflow_definition(name=name, description="original", clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=name)))

    # Break exactly one thing: same name, different clientToken and different description.
    err = _client_error(
        lambda: nova.create_workflow_definition(name=name, description="clobber-attempt", clientToken=_client_token())
    )
    assert err["Code"] == "ConflictException", f"expected ConflictException for a duplicate name, got {err!r}"
    assert err.get("Message") == "Workflow definition already exists", (
        f"expected the exact duplicate-name message, got {err.get('Message')!r}"
    )

    # Effect absent: the original description is unchanged.
    got = nova.get_workflow_definition(workflowDefinitionName=name)
    assert got["description"] == "original", (
        f"rejected duplicate must not clobber the original description, got {got['description']!r}"
    )

    # Positive control, same file: an unused name succeeds, confirmed via an
    # independent read (the terminal assertion must not rest on the mutating call's own
    # response).
    other_name = _wf_name(ctx, "wfdup2")
    other = nova.create_workflow_definition(name=other_name, clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=other_name)))
    assert other["status"] == "ACTIVE", f"expected the unused-name create to report ACTIVE, got {other['status']!r}"
    got_other = nova.get_workflow_definition(workflowDefinitionName=other_name)
    assert got_other["status"] == "ACTIVE", (
        f"expected an independent read of the new definition to report ACTIVE, got {got_other['status']!r}"
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
