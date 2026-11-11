"""integration-type-is-a-per-account-singleton."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-type-is-a-per-account-singleton"
GROUP = 'integrations'
SERVICES = ['cloudwatchomni']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """One AWS_CONFIG_SLREC integration may exist per account: a second create of the same
    type is refused while the first is still present, and an AWS_INTEGRATION with no roleArn
    is refused independently of that singleton.
    """
    cwo = ctx.client("cloudwatchomni")

    name = ctx.unique_name("sim2real-behav-cwo-integ-")
    integration = cwo.create_integration(integrationType="AWS_CONFIG_SLREC", name=name)["integration"]
    integration_id = integration["integrationId"]
    ctx.on_cleanup(_teardown(
        lambda: cwo.delete_integration(identifier={"integrationId": integration_id}),
        "ResourceNotFoundException",
    ))
    assert integration["status"] == "PENDING", f"expected PENDING, got {integration['status']!r}"

    got = cwo.get_integration(identifier={"integrationId": integration_id})["integration"]
    assert got["name"] == name, f"expected {name!r}, got {got['name']!r}"
    assert got["integrationType"] == "AWS_CONFIG_SLREC", (
        f"expected AWS_CONFIG_SLREC, got {got['integrationType']!r}"
    )

    code, message = _error(
        lambda: cwo.create_integration(
            integrationType="AWS_CONFIG_SLREC", name=ctx.unique_name("sim2real-behav-cwo-integ2-")
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == (
        "An integration of type AWS_CONFIG_SLREC already exists for this account"
    ), f"unexpected message {message!r}"

    code, message = _error(
        lambda: cwo.create_integration(
            integrationType="AWS_INTEGRATION", name=ctx.unique_name("sim2real-behav-cwo-integ3-")
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "roleArn cannot be null or empty", f"unexpected message {message!r}"

    found = {item["integrationId"] for item in cwo.list_integrations(integrationType="AWS_CONFIG_SLREC")["items"]}
    assert integration_id in found, f"expected {integration_id!r} in ListIntegrations, got {sorted(found)}"

    cwo.delete_integration(identifier={"integrationId": integration_id})
    code, _ = _error(lambda: cwo.get_integration(identifier={"integrationId": integration_id}))
    assert code == "ResourceNotFoundException", f"expected gone after delete, got {code}"

    # The singleton is freed once the one integration of that type is gone.
    second = cwo.create_integration(
        integrationType="AWS_CONFIG_SLREC", name=ctx.unique_name("sim2real-behav-cwo-integ4-")
    )["integration"]
    ctx.on_cleanup(_teardown(
        lambda: cwo.delete_integration(identifier={"integrationId": second["integrationId"]}),
        "ResourceNotFoundException",
    ))
    assert second["integrationId"] != integration_id, "expected a fresh integration id"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
