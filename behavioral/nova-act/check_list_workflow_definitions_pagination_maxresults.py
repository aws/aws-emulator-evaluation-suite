"""list-workflow-definitions-pagination-maxresults."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-workflow-definitions-pagination-maxresults"
GROUP = "control-plane"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWorkflowDefinitions honors maxResults=1 (one item per page) and nextToken
    pagination eventually surfaces every definition created in this check."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    names = []
    for i in range(3):
        name = _wf_name(ctx, f"wfpg{i}")
        nova.create_workflow_definition(name=name, clientToken=_client_token())
        ctx.on_cleanup(lambda n=name: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=n)))
        names.append(name)

    seen = set()
    next_token = None
    pages = 0
    while pages < 200:
        pages += 1
        kwargs = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = nova.list_workflow_definitions(**kwargs)
        page_names = [s["workflowDefinitionName"] for s in page["workflowDefinitionSummaries"]]
        assert len(page_names) <= 1, "maxResults=1 must return at most one item per page"
        seen.update(page_names)
        next_token = page.get("nextToken")
        if not next_token:
            break

    for name in names:
        assert name in seen, f"{name} never surfaced while paginating ListWorkflowDefinitions"


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
