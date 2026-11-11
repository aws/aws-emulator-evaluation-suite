"""concurrent-update-workflow-run-terminal-status-race."""
from __future__ import annotations

import re
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-update-workflow-run-terminal-status-race"
GROUP = "concurrency"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing UpdateWorkflowRun calls to terminal statuses on one RUNNING run let exactly one win; every
    other caller gets ConflictException or ValidationException, and the run's final status is the
    winner's."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    wf_name = _wf_name(ctx, "wfcrace")
    nova.create_workflow_definition(name=wf_name, clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=wf_name)))

    model_id, version = _pick_model(nova)
    run_id = nova.create_workflow_run(
        workflowDefinitionName=wf_name,
        modelId=model_id,
        clientToken=_client_token(),
        clientInfo={"compatibilityVersion": version, "sdkVersion": "sim2real-behavioral-1.0"},
    )["workflowRunId"]
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id)))

    candidate_statuses = ["SUCCEEDED", "FAILED", "TIMED_OUT", "SUCCEEDED", "FAILED", "TIMED_OUT"]

    def _racer(status):
        try:
            nova.update_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id, status=status)
            return "ok"
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return exc.response["Error"]["Code"]
            raise

    with ThreadPoolExecutor(max_workers=len(candidate_statuses)) as pool:
        results = list(pool.map(_racer, candidate_statuses))

    successes = [r for r in results if r == "ok"]
    losers = [r for r in results if r in ("ConflictException", "ValidationException")]
    assert len(successes) == 1, f"expected exactly one racer to win the terminal transition, got {results}"
    assert len(losers) == len(candidate_statuses) - 1, (
        f"expected the rest to be ConflictException/ValidationException, got {results}"
    )

    winner_status = candidate_statuses[results.index("ok")]
    final = nova.get_workflow_run(workflowDefinitionName=wf_name, workflowRunId=run_id)
    assert final["status"] == winner_status, (
        f"expected the persisted status to match the winning racer's own status {winner_status!r}, "
        f"got {final['status']!r}"
    )


def _wf_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"n{kind}")
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:40]


def _client_token() -> str:
    return uuid.uuid4().hex + "-" + uuid.uuid4().hex


def _pick_model(nova):
    for version in (1, 2, 3, 5, 8, 13, 21):
        resp = nova.list_models(clientCompatibilityVersion=version)
        aliases = resp.get("modelAliases") or []
        ga_aliases = [a["aliasName"] for a in aliases if a.get("aliasName") and "preview" not in a["aliasName"]]
        if ga_aliases:
            return ga_aliases[0], version
        if aliases:
            return aliases[0]["aliasName"], version
    # "nova-act-latest" is a documented, always-available GA alias; CreateWorkflowRun
    # rejects a raw preview modelId directly, so prefer an alias over modelSummaries.
    return "nova-act-latest", 1


def _silent(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
