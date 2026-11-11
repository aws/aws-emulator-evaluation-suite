"""create-workflow-definition-idempotent-same-token."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "create-workflow-definition-idempotent-same-token"
GROUP = "idempotency"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkflowDefinition replayed with the same clientToken and parameters returns ACTIVE with
    the same createdAt, and a unicode/emoji description reads back unchanged after both calls."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    name = _wf_name(ctx, "wfidem")
    token = _client_token()
    description = "idempotency probe \u00e9\u00e8\u00ea \u4e2d\u6587 \U0001f600 \"quoted\""

    first = nova.create_workflow_definition(name=name, description=description, clientToken=token)
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=name)))
    got_1 = nova.get_workflow_definition(workflowDefinitionName=name)
    created_at_1 = got_1["createdAt"]
    assert got_1["description"] == description, (
        f"description did not round-trip: got {got_1['description']!r}"
    )

    second = nova.create_workflow_definition(name=name, description=description, clientToken=token)
    got_2 = nova.get_workflow_definition(workflowDefinitionName=name)
    created_at_2 = got_2["createdAt"]

    assert first["status"] == "ACTIVE", f"expected ACTIVE after create, got {first['status']!r}"
    assert second["status"] == "ACTIVE", f"expected ACTIVE after idempotent replay, got {second['status']!r}"
    assert created_at_1 == created_at_2, "idempotent replay must not re-create the resource"
    assert got_2["description"] == description, "the unicode description must survive the replay unchanged"


def _wf_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"n{kind}")
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:40]


def _client_token() -> str:
    return uuid.uuid4().hex + "-" + uuid.uuid4().hex


def _silent(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
