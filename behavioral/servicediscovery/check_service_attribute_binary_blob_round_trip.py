"""service-attribute-binary-blob-round-trip."""
from __future__ import annotations

import base64
import os
import time

from behavioral_harness import tags

CHECK = "service-attribute-binary-blob-round-trip"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base64-encoded binary blob written via UpdateServiceAttributes survives GetServiceAttributes byte-for-byte."""
    sd = ctx.client("servicediscovery")

    ns_resp = sd.create_http_namespace(Name=ctx.unique_name("simparity-sd-"))
    ns_op = _wait_operation(sd, ns_resp["OperationId"])
    ns_id = ns_op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace_best_effort(sd, ns_id))

    svc = sd.create_service(Name=ctx.unique_name("simparity-sd-svc-"), NamespaceId=ns_id)["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: _delete_service_best_effort(sd, svc_id))

    raw = bytes(range(256)) + os.urandom(127)  # exercise every byte value; length % 3 == 2 forces a "=" pad char
    blob = base64.b64encode(raw).decode("ascii")

    sd.update_service_attributes(ServiceId=svc_id, Attributes={"BINARY_BLOB": blob})

    got = sd.get_service_attributes(ServiceId=svc_id)["ServiceAttributes"]
    got_blob = got["Attributes"]["BINARY_BLOB"]
    assert got_blob == blob, f"base64 blob attribute value was altered on read-back: expected {blob!r}, got {got_blob!r}"
    decoded = base64.b64decode(got_blob)
    assert decoded == raw, f"decoded round-tripped blob does not match original bytes: expected {raw!r}, got {decoded!r}"


def _wait_operation(sd, operation_id, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        status = op["Status"]
        if status == "SUCCESS":
            return op
        if status == "FAIL":
            raise AssertionError(
                f"operation {operation_id} failed: {op.get('ErrorCode')} {op.get('ErrorMessage')}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"operation {operation_id} stuck in {status} after {timeout_s}s")
        time.sleep(interval_s)


def _delete_namespace_best_effort(sd, namespace_id):
    from botocore.exceptions import ClientError

    try:
        op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
        _wait_operation(sd, op_id, timeout_s=180.0)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NamespaceNotFound":
            raise


def _delete_service_best_effort(sd, service_id):
    from botocore.exceptions import ClientError

    try:
        sd.delete_service(Id=service_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServiceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
