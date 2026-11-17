"""register-instance-max-length-id-accepted-in-http-namespace."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-instance-max-length-id-accepted-in-http-namespace"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterInstance accepts a 64-character InstanceId, the InstanceId shape's maximum length,
    on a service in an HTTP namespace, which has no DNS record to turn the id into a DNS label;
    GetInstance reads the full id and its attributes back.
    """
    sd = ctx.client("servicediscovery")

    ns_name = ctx.unique_name("sim2real-behav-sd-ns-http64-")
    namespace_id = _create_http_namespace(ctx, sd, ns_name)

    svc_name = ctx.unique_name("sim2real-behav-sd-svc-http64-")
    service_id = sd.create_service(
        Name=svc_name, NamespaceId=namespace_id, Tags=[{"Key": "Name", "Value": svc_name}]
    )["Service"]["Id"]
    ctx.on_cleanup(lambda: _delete_service(sd, service_id))

    max_length_id = "b" * 64
    attributes = {"CUSTOM_ATTR": "accepted"}
    reg = sd.register_instance(
        ServiceId=service_id, InstanceId=max_length_id, Attributes=attributes
    )
    ctx.on_cleanup(lambda: _deregister_instance(sd, service_id, max_length_id))
    op = _wait_operation(sd, reg["OperationId"])
    assert op["Status"] == "SUCCESS", (
        f"expected a 64-character InstanceId to be accepted on an HTTP-namespace service, "
        f"operation ended in {op['Status']}: {op.get('ErrorMessage')}"
    )

    fetched = sd.get_instance(ServiceId=service_id, InstanceId=max_length_id)["Instance"]
    assert fetched["Id"] == max_length_id, (
        f"GetInstance returned Id {fetched['Id']!r}, expected the 64-character id {max_length_id!r}"
    )
    assert fetched["Attributes"] == attributes, (
        f"GetInstance returned Attributes {fetched['Attributes']!r}, expected {attributes!r}"
    )

    listed = sd.list_instances(ServiceId=service_id)["Instances"]
    assert [i["Id"] for i in listed] == [max_length_id], (
        f"ListInstances returned {listed!r}, expected only the 64-character id"
    )


# =====

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_operation(sd, operation_id, timeout_s=60.0, interval_s=1.5):
    op = _poll_until(
        lambda: sd.get_operation(OperationId=operation_id)["Operation"],
        lambda op: op.get("Status") in ("SUCCESS", "FAIL"),
        timeout_s=timeout_s, interval_s=interval_s,
        description=f"operation {operation_id}",
    )
    return op


def _wait_operation_or_pending(sd, operation_id, timeout_s, interval_s=1.5):
    """The operation at a terminal state, or still non-terminal once ``timeout_s`` runs out.

    A still-pending delete is not a failure: AWS completes it asynchronously past our budget.
    """
    deadline = time.monotonic() + timeout_s
    op = sd.get_operation(OperationId=operation_id)["Operation"]
    while op.get("Status") not in ("SUCCESS", "FAIL") and time.monotonic() < deadline:
        time.sleep(interval_s)
        op = sd.get_operation(OperationId=operation_id)["Operation"]
    return op


def _create_http_namespace(ctx, sd, name) -> str:
    resp = sd.create_http_namespace(Name=name, Tags=[{"Key": "Name", "Value": name}])
    op = _wait_operation(sd, resp["OperationId"])
    if op["Status"] != "SUCCESS":
        raise AssertionError(f"CreateHttpNamespace ended in {op['Status']}: {op.get('ErrorMessage')}")
    namespace_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace(sd, namespace_id))
    return namespace_id


def _delete_namespace(sd, namespace_id) -> None:
    try:
        resp = sd.delete_namespace(Id=namespace_id)
    except sd.exceptions.NamespaceNotFound:
        return
    op = _wait_operation_or_pending(sd, resp["OperationId"], timeout_s=30.0)
    if op["Status"] == "FAIL":
        raise AssertionError(f"DeleteNamespace ended in FAIL: {op.get('ErrorMessage')}")


def _delete_service(sd, service_id) -> None:
    try:
        sd.delete_service(Id=service_id)
    except sd.exceptions.ServiceNotFound:
        return


def _deregister_instance(sd, service_id, instance_id) -> None:
    try:
        resp = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
    except (sd.exceptions.InstanceNotFound, sd.exceptions.ServiceNotFound):
        return
    op = _wait_operation_or_pending(sd, resp["OperationId"], timeout_s=20.0)
    if op["Status"] == "FAIL":
        raise AssertionError(f"DeregisterInstance ended in FAIL: {op.get('ErrorMessage')}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
