"""create-workload-identity-missing-role-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-workload-identity-missing-role-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkloadIdentity with a name containing spaces is refused with ValidationException and the exact pattern
    message and creates nothing; a valid name is created, listed and read back, and after delete Get answers
    ResourceNotFoundException "WorkloadIdentity with id <name> not found."."""
    client = ctx.client("bedrock-agentcore-control")

    # Embedding a space forces a mismatch against the documented name pattern
    # `[A-Za-z0-9_.-]+`, which only allows letters, digits, underscore, dot, hyphen.
    bad_name = ctx.unique_name("sim2real-wi-bad-").replace("-", " ")
    code, message = _error_detail(lambda: client.create_workload_identity(name=bad_name))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "1 validation error detected: Value at 'name' failed to satisfy constraint: Member must satisfy regular expression pattern: [A-Za-z0-9_.-]+"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no workload identity exists under the malformed name.
    assert not _workload_identity_name_exists(client, bad_name), (
        f"workload identity {bad_name!r} exists despite the rejected create"
    )

    # Positive control: a pattern-valid name succeeds and round-trips through
    # Get/List/Delete.
    good_name = _pattern_safe_name(ctx, "sim2realwivalid")
    created = client.create_workload_identity(
        name=good_name, tags={"sim2real:managed": "true", "sim2real:check": CHECK}
    )
    ctx.on_cleanup(lambda: _best_effort_delete(client, good_name))
    assert created["name"] == good_name, f"expected name={good_name!r}, got {created['name']!r}"
    assert _workload_identity_name_exists(client, good_name), (
        f"workload identity {good_name!r} missing from ListWorkloadIdentities after create"
    )

    got = client.get_workload_identity(name=good_name)
    assert got["name"] == good_name, f"expected name={good_name!r}, got {got['name']!r}"

    client.delete_workload_identity(name=good_name)
    assert not _workload_identity_name_exists(client, good_name), (
        f"workload identity {good_name!r} still listed after delete"
    )
    post_delete_code, post_delete_message = _error_detail(lambda: client.get_workload_identity(name=good_name))
    assert post_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {post_delete_code}"
    )
    expected_post_delete_message = f"WorkloadIdentity with id {good_name} not found."
    assert post_delete_message == expected_post_delete_message, f"expected message {expected_post_delete_message!r}, got {post_delete_message!r}"


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c in "_.-")
    if len(safe) < 3:
        safe = (safe + "abc")[:3]
    return safe[:255]


def _workload_identity_name_exists(client, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_workload_identities(**kwargs)
        for item in page.get("workloadIdentities", []):
            if item.get("name") == name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


def _best_effort_delete(client, name: str) -> None:
    try:
        client.delete_workload_identity(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
