"""get-connector-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-connector-not-found"
GROUP = "not-found"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConnector on a syntactically valid but nonexistent ConnectorArn returns
    ResourceNotFoundException, and a plain ListConnectors call in the same file proves the
    endpoint is otherwise healthy.
    """
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    connector_arn = f"arn:aws:pca-connector-ad:{ctx.region}:{account}:connector/{uuid.uuid4()}"

    code, message = _error_code(lambda: pcad.get_connector(ConnectorArn=connector_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent connector, got {code!r}"
    )
    assert message == f"Connector was not found: {connector_arn}.", message

    control = pcad.list_connectors()
    assert "Connectors" in control, (
        f"expected a well-formed ListConnectors response, got {control!r}"
    )


def _error_code(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
