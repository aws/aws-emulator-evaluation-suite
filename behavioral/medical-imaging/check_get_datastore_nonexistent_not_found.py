"""get-datastore-nonexistent-not-found."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-datastore-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["medical-imaging"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    accepting a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}"
    )


def _create_datastore_retry(mi, ctx, timeout_s: float = 180.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mi.create_datastore(
                datastoreName=name, clientToken=token, tags={"sim2real": "true"}
            )["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _delete_datastore_retry(mi, datastore_id: str, timeout_s: float = 900.0) -> None:
    deadline = time.monotonic() + timeout_s
    delay = 10.0
    while True:
        try:
            mi.delete_datastore(datastoreId=datastore_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # HealthImaging's edge throttle can return a compound code like
            # "ThrottlingException, TooManyRequestsException" rather than either alone.
            is_throttle = "ThrottlingException" in code or "TooManyRequestsException" in code
            if is_throttle and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.6, 120.0)
                continue
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDatastore for a syntactically valid but nonexistent datastoreId raises
    ResourceNotFoundException, while a real, well-formed datastoreId still succeeds (positive
    control) in the same run."""
    mi = ctx.client("medical-imaging")

    # Positive control: a real datastoreId succeeds first, so the account and credentials are
    # otherwise healthy and the rejection below cannot be "every GetDatastore call fails".
    datastore_id = _create_datastore_retry(mi, ctx)
    ctx.on_cleanup(lambda: _delete_datastore_retry(mi, datastore_id))
    got = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]
    assert got["datastoreId"] == datastore_id, (
        f"positive control returned datastoreId {got['datastoreId']!r}, expected {datastore_id!r}"
    )

    # Drain to ACTIVE so cleanup's DeleteDatastore does not race a still-CREATING datastore.
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"] == "ACTIVE":
            break
        time.sleep(3)

    bogus_id = "0" * 32
    assert bogus_id != datastore_id, "the random bogus id collided with the real one"
    error = _client_error(lambda: mi.get_datastore(datastoreId=bogus_id))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"GetDatastore on a syntactically valid but nonexistent id returned "
        f"{error.get('Code')!r}, expected 'ResourceNotFoundException'"
    )
    expected_message = "Datastore resource is not found."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
