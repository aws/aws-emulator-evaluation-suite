"""workload-identity-lifecycle-transitions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workload-identity-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkloadIdentity returns the name and an ARN, UpdateWorkloadIdentity's return URLs read back, and after
    delete Get and Update answer ResourceNotFoundException "WorkloadIdentity with id <name> not found."."""
    bac = ctx.client("bedrock-agentcore-control")
    name = ctx.unique_name("sim2real-wi-")

    create_resp = bac.create_workload_identity(name=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_workload_identity(name=name)))
    assert create_resp["name"] == name, f"expected name={name!r}, got {create_resp['name']!r}"
    assert create_resp["workloadIdentityArn"], "CreateWorkloadIdentity returned an empty ARN"

    got = bac.get_workload_identity(name=name)
    assert got["name"] == name, f"GetWorkloadIdentity name mismatch: expected {name!r}, got {got['name']!r}"

    update_resp = bac.update_workload_identity(
        name=name, allowedResourceOauth2ReturnUrls=["https://example.com/callback"]
    )
    assert update_resp["allowedResourceOauth2ReturnUrls"] == ["https://example.com/callback"], (
        f"UpdateWorkloadIdentity did not echo the new return URLs: {update_resp['allowedResourceOauth2ReturnUrls']!r}"
    )

    got2 = bac.get_workload_identity(name=name)
    assert got2["allowedResourceOauth2ReturnUrls"] == ["https://example.com/callback"], (
        f"independent read after update expected the persisted return URLs, got {got2['allowedResourceOauth2ReturnUrls']!r}"
    )

    bac.delete_workload_identity(name=name)
    expected_message = f"WorkloadIdentity with id {name} not found."
    code, message = _client_error(lambda: bac.get_workload_identity(name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _client_error(
        lambda: bac.update_workload_identity(
            name=name, allowedResourceOauth2ReturnUrls=["https://example.com/dead"]
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateWorkloadIdentity on a deleted identity to fail with ResourceNotFoundException, got {update_code!r}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )


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
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
