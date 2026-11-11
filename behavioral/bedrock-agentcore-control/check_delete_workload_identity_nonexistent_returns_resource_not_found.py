"""delete-workload-identity-nonexistent-returns-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-workload-identity-nonexistent-returns-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkloadIdentity against an unknown identity returns ResourceNotFoundException.
    Deletion is also NOT assumed idempotent: deleting the same (now-deleted) real identity
    a second time must again return ResourceNotFoundException rather than a silent success."""
    client = ctx.client("bedrock-agentcore-control")

    real_name = ctx.unique_name("sim2real-wi-del-")
    client.create_workload_identity(name=real_name)
    ctx.on_cleanup(lambda: _best_effort_delete(client, real_name))

    fake_name = ctx.unique_name("sim2real-wi-del-missing-")
    code, message = _error(lambda: client.delete_workload_identity(name=fake_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"WorkloadIdentity with name {fake_name} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the real identity still exists and can be deleted for real.
    got = client.get_workload_identity(name=real_name)
    assert got["name"] == real_name, f"expected {real_name!r}, got {got['name']!r}"
    client.delete_workload_identity(name=real_name)

    # Effect confirmed: the real identity is now actually gone.
    code2, message2 = _error(lambda: client.get_workload_identity(name=real_name))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected2 = f"WorkloadIdentity with id {real_name} not found."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # Delete is NOT idempotent: deleting the already-deleted real identity again must
    # still return ResourceNotFoundException, not a silent 2xx.
    code3, message3 = _error(lambda: client.delete_workload_identity(name=real_name))
    assert code3 == "ResourceNotFoundException", f"expected ResourceNotFoundException on redelete, got {code3}"
    expected3 = f"WorkloadIdentity with name {real_name} not found."
    assert message3 == expected3, f"expected message {expected3!r}, got {message3!r}"


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete(client, name: str) -> None:
    try:
        client.delete_workload_identity(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
