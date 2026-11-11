"""workload-identity-update-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workload-identity-update-roundtrip"
GROUP = "state"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkloadIdentity persists the given return URLs, UpdateWorkloadIdentity
    replaces them, and DeleteWorkloadIdentity makes the resource unreachable."""
    control = ctx.client("bedrock-agentcore-control")
    name = ctx.unique_name("sim2real-wid-")

    control.create_workload_identity(
        name=name,
        allowedResourceOauth2ReturnUrls=["https://example.com/callback-1"],
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: control.delete_workload_identity(name=name)))

    created = control.get_workload_identity(name=name)
    assert created["allowedResourceOauth2ReturnUrls"] == ["https://example.com/callback-1"], (
        f"expected ['https://example.com/callback-1'], got {created['allowedResourceOauth2ReturnUrls']!r}"
    )

    control.update_workload_identity(
        name=name, allowedResourceOauth2ReturnUrls=["https://example.com/callback-2"]
    )
    updated = control.get_workload_identity(name=name)
    assert updated["allowedResourceOauth2ReturnUrls"] == ["https://example.com/callback-2"], (
        f"expected update to replace with ['https://example.com/callback-2'], "
        f"got {updated['allowedResourceOauth2ReturnUrls']!r}"
    )

    control.delete_workload_identity(name=name)
    code, message = _client_error(lambda: control.get_workload_identity(name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"WorkloadIdentity with id {name} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
