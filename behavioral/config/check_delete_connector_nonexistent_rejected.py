"""delete-connector-nonexistent-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-connector-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["config"]

_INVALID_ARN_MESSAGE = "The connector ARN provided is not valid."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConnector and GetConnector on a connector ARN that never existed fail with ValidationException
    "The connector ARN provided is not valid.", and ListConnectors is unchanged by the delete."""
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    def _list_all_connector_arns():
        arns = []
        next_token = None
        while True:
            kwargs = {"NextToken": next_token} if next_token else {}
            resp = config.list_connectors(**kwargs)
            arns.extend(s["arn"] for s in resp.get("ConnectorSummaries", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return arns

    baseline_arns = _list_all_connector_arns()

    fake_arn = f"arn:aws:config:{ctx.region}:{account_id}:connector/sim2real-does-not-exist-{uuid.uuid4()}"

    # Break exactly one thing: delete a connector ARN that was never created.
    code, message = _error_code(lambda: config.delete_connector(Arn=fake_arn))
    assert code == "ValidationException", f"expected a rejection, got {code}"
    assert message == _INVALID_ARN_MESSAGE, f"expected the invalid-ARN message, got {message!r}"

    # Effect absent: the connector inventory is byte-for-byte unchanged by the rejected delete.
    after = _list_all_connector_arns()
    assert after == baseline_arns, (baseline_arns, after)

    # Contrast: GetConnector on the same never-created ARN is rejected the same way, not with a
    # different/looser answer (e.g. an empty success).
    get_code, get_message = _error_code(lambda: config.get_connector(Arn=fake_arn))
    assert get_code == "ValidationException", f"expected a rejection, got {get_code}"
    assert get_message == _INVALID_ARN_MESSAGE, f"expected the invalid-ARN message, got {get_message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

