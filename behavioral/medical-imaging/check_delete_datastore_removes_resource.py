"""delete-datastore-removes-resource."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-datastore-removes-resource"
GROUP = "state"
SERVICES = ["medical-imaging"]


def _create_datastore_retry(mi, ctx, timeout_s: float = 1500.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    delay = 10.0
    while True:
        try:
            return mi.create_datastore(datastoreName=name, clientToken=token)["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.6, 120.0)
                continue
            raise


def _delete_datastore_retry(mi, datastore_id: str, timeout_s: float = 2400.0):
    deadline = time.monotonic() + timeout_s
    delay = 15.0
    while True:
        try:
            return mi.delete_datastore(datastoreId=datastore_id)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.6, 150.0)
                continue
            raise




def _wait_active(mi, datastore_id: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError("datastore never reached ACTIVE")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDatastore transitions an ACTIVE datastore through DELETING to a terminal state:
    either an observable DELETED status, or the datastore is purged outright such that
    GetDatastore starts raising ResourceNotFoundException."""
    mi = ctx.client("medical-imaging")
    datastore_id = _create_datastore_retry(mi, ctx)

    def _cleanup_delete():
        try:
            _delete_datastore_retry(mi, datastore_id, timeout_s=120.0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_delete)
    _wait_active(mi, datastore_id)

    del_resp = _delete_datastore_retry(mi, datastore_id)
    assert del_resp["datastoreStatus"] == "DELETING", del_resp["datastoreStatus"]

    final_status = None
    purged = False
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            final_status = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                purged = True
                break
            raise
        if final_status == "DELETED":
            break
        time.sleep(3)

    assert purged or final_status == "DELETED", (
        f"datastore did not reach a terminal deleted state, last status={final_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
