"""cloud-connector-delete-during-update-conflict-rejected."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "cloud-connector-delete-during-update-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent Delete/UpdateCloudConnector on a never-created id both fail with
    ResourceNotFoundException, never ConflictException or success; ListCloudConnectors still works.
    """
    ssm = ctx.client("ssm")
    fake_id = str(uuid.uuid4())

    def _update() -> dict:
        return _error_code(
            lambda: ssm.update_cloud_connector(CloudConnectorId=fake_id, DisplayName="race-update")
        )

    def _delete() -> dict:
        return _error_code(lambda: ssm.delete_cloud_connector(CloudConnectorId=fake_id))

    with ThreadPoolExecutor(max_workers=2) as pool:
        update_future = pool.submit(_update)
        delete_future = pool.submit(_delete)
        update_err = update_future.result()
        delete_err = delete_future.result()

    assert update_err["Code"] == "ResourceNotFoundException", update_err
    assert update_err.get("Message") == "CloudConnector not found for account.", update_err
    assert delete_err["Code"] == "ResourceNotFoundException", delete_err
    assert delete_err.get("Message") == "CloudConnector not found for account.", delete_err

    # Positive control: the rejections are specific to the id, not an unreachable endpoint.
    list_resp = ssm.list_cloud_connectors()
    assert list_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, list_resp

    # The race must not leave the connector half created.
    follow_up_err = _delete()
    assert follow_up_err["Code"] == "ResourceNotFoundException", follow_up_err
    assert follow_up_err.get("Message") == "CloudConnector not found for account.", follow_up_err


def _error_code(fn):
    """Call fn(); return its botocore Error dict, raising if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
