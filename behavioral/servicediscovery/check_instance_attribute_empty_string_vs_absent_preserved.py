"""instance-attribute-empty-string-vs-absent-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "instance-attribute-empty-string-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterInstance attribute explicitly set to "" stays present-and-empty; an omitted key stays absent from GetInstance."""
    sd = ctx.client("servicediscovery")

    ns_resp = sd.create_http_namespace(
        Name=ctx.unique_name("simparity-sd-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ns_op = _wait_operation(sd, ns_resp["OperationId"])
    ns_id = ns_op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace_best_effort(sd, ns_id))

    svc = sd.create_service(
        Name=ctx.unique_name("simparity-sd-svc-"),
        NamespaceId=ns_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: _delete_service_best_effort(sd, svc_id))

    instance_id = ctx.unique_name("simparity-sd-inst-")
    reg_resp = sd.register_instance(
        ServiceId=svc_id,
        InstanceId=instance_id,
        Attributes={"CUSTOM_EMPTY": "", "CUSTOM_PRESENT": "value1"},
    )
    _wait_operation(sd, reg_resp["OperationId"], timeout_s=120.0)
    ctx.on_cleanup(lambda: _deregister_instance_best_effort(sd, svc_id, instance_id))

    instance = sd.get_instance(ServiceId=svc_id, InstanceId=instance_id)["Instance"]
    attrs = instance["Attributes"]

    assert "CUSTOM_EMPTY" in attrs, "explicitly-empty attribute key vanished from GetInstance"
    assert attrs["CUSTOM_EMPTY"] == "", "explicitly-empty attribute value was not preserved as empty string"
    assert attrs["CUSTOM_PRESENT"] == "value1", (
        f"non-empty attribute value corrupted on read-back: got {attrs['CUSTOM_PRESENT']!r}"
    )
    assert "CUSTOM_ABSENT" not in attrs, "an omitted attribute key must not materialize on read-back"


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


def _deregister_instance_best_effort(sd, service_id, instance_id):
    from botocore.exceptions import ClientError

    try:
        op_id = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
        _wait_operation(sd, op_id, timeout_s=120.0)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InstanceNotFound", "ServiceNotFound"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
