"""create-workflow-definition-invalid-name-pattern-rejected."""
from __future__ import annotations

import re
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-workflow-definition-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["nova-act"]
# Nova Act serves its API from us-east-1 only.
NOVA_ACT_REGION = "us-east-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWorkflowDefinition with a name outside ^[a-zA-Z0-9_-]{1,40}$ fails with ValidationException
    and the exact message and stores no definition under that name; a compliant name is created
    ACTIVE and reads back."""
    nova = ctx.client("nova-act", region=NOVA_ACT_REGION)
    invalid_name = "bad name with spaces!"

    before = _all_names(nova)

    # Break exactly one thing: an out-of-pattern name.
    err = _client_error(lambda: nova.create_workflow_definition(name=invalid_name, clientToken=_client_token()))
    assert err["Code"] == "ValidationException", (
        f"CreateWorkflowDefinition({invalid_name!r}) returned {err!r}, expected 'ValidationException'"
    )
    expected = (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9_-]{1,40}"
    )
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    # Effect absent, via an independent read: GetWorkflowDefinition validates the same
    # ^[a-zA-Z0-9_-]{1,40}$ pattern, so the invalid name itself can never be queried back. Other
    # runs create and delete definitions in the account meanwhile, so the proof is that no
    # definition new since the first listing carries the invalid name, as given or with its
    # out-of-pattern characters dropped or replaced.
    after = _all_names(nova)
    stored = sorted(n for n in after - before if _letters(invalid_name) in _letters(n))
    assert not stored, (
        f"the rejected CreateWorkflowDefinition({invalid_name!r}) left workflow definitions "
        f"behind: {stored!r}"
    )

    # Positive control, same file: a compliant name succeeds and is independently readable.
    valid_name = _wf_name(ctx, "wfvalid")
    created = nova.create_workflow_definition(name=valid_name, clientToken=_client_token())
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=valid_name)))
    assert created["status"] == "ACTIVE", (
        f"CreateWorkflowDefinition({valid_name!r}) returned status {created['status']!r}, "
        f"expected 'ACTIVE'"
    )

    fetched = nova.get_workflow_definition(workflowDefinitionName=valid_name)
    assert fetched["name"] == valid_name and fetched["status"] == "ACTIVE", (
        f"an independent GetWorkflowDefinition({valid_name!r}) returned "
        f"name={fetched.get('name')!r} status={fetched.get('status')!r}, expected "
        f"name={valid_name!r} status='ACTIVE'"
    )


def _letters(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _all_names(nova) -> set[str]:
    names: set[str] = set()
    next_token = None
    while True:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = nova.list_workflow_definitions(**kwargs)
        names.update(s["workflowDefinitionName"] for s in page["workflowDefinitionSummaries"])
        next_token = page.get("nextToken")
        if not next_token:
            return names


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
