"""update-workload-identity-nonexistent-returns-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-workload-identity-nonexistent-returns-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkloadIdentity against an unknown identity name returns
    ResourceNotFoundException, does not create a phantom identity, and a real identity
    is still updatable afterwards (positive control)."""
    client = ctx.client("bedrock-agentcore-control")

    real_name = ctx.unique_name("sim2real-wi-")
    client.create_workload_identity(name=real_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _best_effort_delete_workload_identity(client, real_name))

    fake_name = ctx.unique_name("sim2real-wi-missing-")

    code, message = _client_error(
        lambda: client.update_workload_identity(
            name=fake_name, allowedResourceOauth2ReturnUrls=["https://example.com/cb"]
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"WorkloadIdentity with id {fake_name} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the failed update did not create the identity it referenced.
    code2, message2 = _client_error(lambda: client.get_workload_identity(name=fake_name))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected2 = f"WorkloadIdentity with id {fake_name} not found."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # Positive control: updating the real identity succeeds and persists.
    client.update_workload_identity(
        name=real_name, allowedResourceOauth2ReturnUrls=["https://example.com/callback"]
    )
    got = client.get_workload_identity(name=real_name)
    assert got["allowedResourceOauth2ReturnUrls"] == ["https://example.com/callback"], (
        f"expected update to persist, got {got.get('allowedResourceOauth2ReturnUrls')!r}"
    )


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _best_effort_delete_workload_identity(client, name: str) -> None:
    try:
        client.delete_workload_identity(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
