"""get-datastore-malformed-id-validation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-datastore-malformed-id-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["medical-imaging"]


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises,
    because an over-permissive target accepting input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_datastore_retry(mi, ctx, timeout_s: float = 180.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mi.create_datastore(
                datastoreName=name,
                clientToken=token,
                tags={"env": "sim2real", "owner": "behavioral"},
            )["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDatastore rejects a datastoreId that fails the ^[0-9a-z]{32}$ pattern with
    ValidationException, while a real, well-formed datastoreId still succeeds (positive
    control) in the same run."""
    mi = ctx.client("medical-imaging")

    malformed_id = "not-a-valid-datastore-id!!"
    code, message = _client_error(lambda: mi.get_datastore(datastoreId=malformed_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: datastoreId failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [0-9a-z]{32}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a well-formed, real datastoreId still succeeds.
    datastore_id = _create_datastore_retry(mi, ctx)
    ctx.on_cleanup(lambda: mi.delete_datastore(datastoreId=datastore_id))

    got = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]
    assert got["datastoreId"] == datastore_id, (
        f"expected datastoreId {datastore_id!r}, got {got['datastoreId']!r}"
    )
    assert got["datastoreStatus"] in ("CREATING", "ACTIVE"), (
        f"expected CREATING or ACTIVE right after create, got {got['datastoreStatus']!r}"
    )

    # Drain to ACTIVE so cleanup's DeleteDatastore does not race a still-CREATING datastore.
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"] == "ACTIVE":
            break
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
