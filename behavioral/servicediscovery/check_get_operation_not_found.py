"""get-operation-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-operation-not-found"
GROUP = 'operations'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOperation on a well-formed, never-issued OperationId fails with OperationNotFound and an empty
    message, while GetOperation on an id the check just received succeeds."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
        raise AssertionError("expected a ClientError, call succeeded")

    def _poll_operation(operation_id, timeout_s=180.0, interval_s=3.0):
        deadline = time.monotonic() + timeout_s
        op = None
        while time.monotonic() < deadline:
            op = sd.get_operation(OperationId=operation_id)["Operation"]
            if op["Status"] in ("SUCCESS", "FAIL"):
                return op
            time.sleep(interval_s)
        raise AssertionError(
            f"operation {operation_id} did not reach a terminal state within {timeout_s}s "
            f"(last status={op['Status'] if op else None})"
        )

    name = ctx.unique_name("sim2real-behav-httpns-")
    real_op_id = sd.create_http_namespace(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["OperationId"]

    def _cleanup():
        op = _poll_operation(real_op_id)
        if op["Status"] == "SUCCESS":
            del_op_id = sd.delete_namespace(Id=op["Targets"]["NAMESPACE"])["OperationId"]
            _poll_operation(del_op_id)

    ctx.on_cleanup(_cleanup)

    # Positive control: GetOperation on the id this check just issued succeeds.
    positive = sd.get_operation(OperationId=real_op_id)["Operation"]
    assert positive["Id"] == real_op_id, f"expected operation {real_op_id}, got {positive.get('Id')}"

    bogus_op_id = ctx.unique_name("sim2real-behav-op-bogus-")
    code, message = _error(lambda: sd.get_operation(OperationId=bogus_op_id))
    assert code == "OperationNotFound", f"expected OperationNotFound, got {code}"
    assert message == "", f"expected GetOperation's OperationNotFound to carry an empty message, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
