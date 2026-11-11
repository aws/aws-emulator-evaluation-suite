"""validate-cloud-connector-unknown-id-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "validate-cloud-connector-unknown-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateCloudConnector on a well-formed but unknown id fails with ResourceNotFoundException
    rather than succeeding, and no connector materializes; ListCloudConnectors still works.
    """
    ssm = ctx.client("ssm")

    fake_id = str(uuid.uuid4())

    # Positive control on the same subsystem: a real connector needs an external cloud tenant.
    listing = ssm.list_cloud_connectors()
    assert "CloudConnectors" in listing, f"ListCloudConnectors response missing key: {listing}"
    listed_ids = {c["CloudConnectorId"] for c in listing["CloudConnectors"]}
    assert fake_id not in listed_ids, f"fresh uuid {fake_id} unexpectedly already listed"

    code, message = _error(lambda: ssm.validate_cloud_connector(CloudConnectorId=fake_id))
    assert code == "ResourceNotFoundException", f"unexpected code: {code}"
    assert message == 'CloudConnector not found for account.', f"unexpected message: {message!r}"

    # Effect absent: no connector materialized as a side effect of the failed validation call.
    get_code, get_message = _error(lambda: ssm.get_cloud_connector(CloudConnectorId=fake_id))
    assert get_code == "ResourceNotFoundException", f"unexpected code: {get_code}"
    assert get_message == 'CloudConnector not found for account.', f"unexpected message: {get_message!r}"


def _error(fn):
    """Call fn(); return its (code, message), raising if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
