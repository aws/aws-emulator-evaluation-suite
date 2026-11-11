"""concurrent-create-workflow-definition-same-name-race."""
from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-create-workflow-definition-same-name-race"
GROUP = "concurrency"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers calling CreateWorkflowDefinition for the same name (distinct clientTokens,
    so none can win via idempotent replay) must yield exactly one winner; every other
    racer must fail with ConflictException, and the name stays a single resource."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    name = _wf_name(ctx, "wfrace")
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=name)))

    racer_count = 6

    def _racer(i):
        try:
            nova.create_workflow_definition(
                name=name, description=f"racer-{i}", clientToken=_client_token()
            )
            return "ok"
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return exc.response["Error"]["Code"]
            raise

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    successes = [r for r in results if r == "ok"]
    conflicts = [r for r in results if r == "ConflictException"]
    assert len(successes) == 1, f"expected exactly one winner, got {results}"
    assert len(conflicts) == racer_count - 1, f"expected the rest to be ConflictException, got {results}"

    listed = nova.list_workflow_definitions()
    matching = [s for s in listed["workflowDefinitionSummaries"] if s["workflowDefinitionName"] == name]
    assert len(matching) == 1, "the race must not create more than one definition with this name"


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
