"""delete-connector-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "delete-connector-not-found"
GROUP = "state-machine"
SERVICES = ["pca-connector-ad"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConnector on a well-formed nonexistent ConnectorArn succeeds (HTTP 200 or 202) twice, and
    GetConnector on that ARN still gets ResourceNotFoundException "Connector was not found: <arn>.", so
    the deletes created nothing."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    connector_arn = f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/{uuid.uuid4()}"

    first = pcad.delete_connector(ConnectorArn=connector_arn)
    status = first["ResponseMetadata"]["HTTPStatusCode"]
    assert status in (200, 202), (
        f"expected DeleteConnector on a syntactically valid but nonexistent ARN to succeed "
        f"(200/202) rather than raise ResourceNotFoundException, got HTTP {status}"
    )

    # calling it again on the same nonexistent ARN must be equally tolerant (no state
    # flip from "accepted" to "not found" on repetition).
    second = pcad.delete_connector(ConnectorArn=connector_arn)
    status2 = second["ResponseMetadata"]["HTTPStatusCode"]
    assert status2 in (200, 202), (
        f"expected the repeated DeleteConnector on the same still-nonexistent ARN to be equally "
        f"tolerant, got HTTP {status2}"
    )

    # GetConnector on that same never-existent ARN must still hard-fail: proves DeleteConnector's
    # tolerance is a no-op rather than having conjured a phantom resource into existence.
    code, message = _error_code(lambda: pcad.get_connector(ConnectorArn=connector_arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetConnector on the still-nonexistent ARN to raise ResourceNotFoundException "
        f"after two tolerant deletes, got {code!r}"
    )
    assert message == f"Connector was not found: {connector_arn}.", message

    control = pcad.list_connectors()
    assert "Connectors" in control, (
        f"expected ListConnectors response to contain 'Connectors', got keys {list(control)}"
    )


def _error_code(fn):
    """Call fn(); return its error (code, message). A success raises, because a target that
    accepts what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
