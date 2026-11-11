"""e2e-connector-malformed-arn-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "e2e-connector-malformed-arn-rejected"
GROUP = "e2e"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConnector/DeleteConnector reject both a malformed and a well-formed but nonexistent
    connector ARN with ValidationException and the same message, leaving the connector list intact.
    """
    config = ctx.client("config")
    # PutConnector verifies Azure credentials, so no real connector can be provisioned;
    # ListConnectors is the positive control and the effect-absent baseline.
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    before = config.list_connectors().get("ConnectorSummaries", [])

    malformed = "not-a-valid-connector-arn"
    well_formed_nonexistent = (
        f"arn:aws:config:{ctx.region}:{account_id}:connector/sim2real-does-not-exist-{uuid.uuid4()}"
    )

    code, message = _error(lambda: config.get_connector(Arn=malformed))
    assert code == "ValidationException", f"expected ValidationException from Get, got {code}"
    assert message == _INVALID_ARN, f"expected the exact invalid-ARN message from Get, got {message!r}"

    code, message = _error(lambda: config.delete_connector(Arn=malformed))
    assert code == "ValidationException", f"expected ValidationException from Delete, got {code}"
    assert message == _INVALID_ARN, f"expected the exact invalid-ARN message from Delete, got {message!r}"

    # Contrast: a well-formed but never-created ARN is rejected too, and AWS
    # answers it with the same invalid-ARN message as the malformed one.
    code, message = _error(lambda: config.get_connector(Arn=well_formed_nonexistent))
    assert code == "ValidationException", (
        f"expected Get to reject a well-formed but nonexistent ARN, got {code}"
    )
    assert message == _INVALID_ARN, (
        f"expected Get to answer a well-formed but nonexistent ARN with the exact "
        f"invalid-ARN message, got {message!r}"
    )

    code, message = _error(lambda: config.delete_connector(Arn=well_formed_nonexistent))
    assert code == "ValidationException", (
        f"expected Delete to reject a well-formed but nonexistent ARN, got {code}"
    )
    assert message == _INVALID_ARN, (
        f"expected Delete to answer a well-formed but nonexistent ARN with the exact "
        f"invalid-ARN message, got {message!r}"
    )

    # Effect absent: none of the four rejected calls changed the connector inventory.
    after = config.list_connectors().get("ConnectorSummaries", [])
    assert after == before, f"a rejected Get/DeleteConnector must not change the connector list: before={before!r} after={after!r}"


_INVALID_ARN = "The connector ARN provided is not valid."


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
