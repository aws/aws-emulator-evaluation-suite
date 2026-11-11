"""workflow-definition-delete-transitions-to-deleting."""
from __future__ import annotations

import re
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "workflow-definition-delete-transitions-to-deleting"
GROUP = "state"
SERVICES = ["nova-act"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteWorkflowDefinition on an ACTIVE definition answers DELETING, and an immediate
    GetWorkflowDefinition and a second delete both fail with ResourceNotFoundException and the exact
    message."""
    nova = _nova_client(ctx)
    name = _wf_name(ctx, "wddel")

    nova.create_workflow_definition(name=name, clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=name)))

    got = nova.get_workflow_definition(workflowDefinitionName=name)
    assert got["status"] == "ACTIVE", f"expected freshly-created definition ACTIVE, got {got['status']!r}"

    delete_resp = nova.delete_workflow_definition(workflowDefinitionName=name)
    assert delete_resp["status"] == "DELETING", (
        f"expected DeleteWorkflowDefinition's own response to report DELETING, got {delete_resp['status']!r}"
    )

    def _probe():
        from botocore.exceptions import ClientError

        try:
            nova.get_workflow_definition(workflowDefinitionName=name)
        except ClientError as exc:
            err = exc.response["Error"]
            return err.get("Code"), err.get("Message")
        return "still-readable", None

    code, message = _poll_until(
        _probe, lambda r: r[0] == "ResourceNotFoundException", timeout_s=120.0, interval_s=3.0
    )
    assert code == "ResourceNotFoundException", (
        f"expected an independent GetWorkflowDefinition to eventually see ResourceNotFoundException, got {code!r}"
    )
    expected_get_message = "Workflow definition not found"
    assert message == expected_get_message, f"expected message {expected_get_message!r}, got {message!r}"

    second_delete_code, second_delete_message = _error(
        lambda: nova.delete_workflow_definition(workflowDefinitionName=name)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a delete of the already-gone definition to also fail not-found, got {second_delete_code!r}"
    )
    expected_delete_message = "Workflow definition not found"
    assert second_delete_message == expected_delete_message, (
        f"expected message {expected_delete_message!r}, got {second_delete_message!r}"
    )


def _nova_client(ctx):
    """Nova Act's control plane is served only in us-east-1, whatever the run's default
    region; pin the region on the client so every target gets the same request."""
    return ctx.client("nova-act", region="us-east-1")  # region-pinned: control plane is us-east-1 only


def _wf_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"n{kind}")
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:40]


def _client_token() -> str:
    return uuid.uuid4().hex + "-" + uuid.uuid4().hex


def _error(fn):
    """The (code, message) of the refusal ``fn`` provokes; raises if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _silent(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
