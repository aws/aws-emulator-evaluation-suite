"""deregister-instance-not-registered-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-instance-not-registered-error"
GROUP = 'instance-lifecycle'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterInstance on an InstanceId that was never registered under the Service must fail
    with InstanceNotFound -- and the same InstanceId, once actually registered, must deregister
    cleanly, proving the earlier failure was absence and not a malformed id."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
        raise AssertionError("expected a ClientError but the call succeeded")

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _wait_for_operation(operation_id, timeout_s=60, interval_s=1.5):
        # Poll GetOperation until it reaches a terminal state (SUCCESS or FAIL).
        return _poll_until(
            lambda: sd.get_operation(OperationId=operation_id)["Operation"],
            lambda op: op.get("Status") in ("SUCCESS", "FAIL"),
            timeout_s=timeout_s, interval_s=interval_s,
        )

    def _delete_namespace(namespace_id, wait=True):
        resp = sd.delete_namespace(Id=namespace_id)
        if wait:
            return _wait_for_operation(resp["OperationId"])
        return resp

    def _unless_gone(delete, gone_code):
        # Teardown: an already-deleted resource answers its documented not-found code.
        try:
            delete()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != gone_code:
                raise

    def _create_http_namespace(name, **kwargs):
        resp = sd.create_http_namespace(
            Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs
        )
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_namespace(namespace_id), "NamespaceNotFound"))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(
            Name=name, NamespaceId=namespace_id,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs
        )["Service"]["Id"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: sd.delete_service(Id=service_id), "ServiceNotFound"))
        return service_id

    def _register_instance(instance_id):
        resp = sd.register_instance(
            ServiceId=service_id, InstanceId=instance_id, Attributes={"custom-attr": "v1"}
        )
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"RegisterInstance failed: {op}")

    def _deregister_instance(instance_id):
        resp = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"DeregisterInstance failed: {op}")

    def _instance_ids():
        ids = set()
        for page in sd.get_paginator("list_instances").paginate(ServiceId=service_id):
            ids.update(inst["Id"] for inst in page.get("Instances", []))
        return ids

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-dereg-"))
    service_id = _create_service(ctx.unique_name("sim2real-behav-sd-svc-dereg-"), namespace_id)

    # Positive control: prove DeregisterInstance actually works on this service before trusting
    # a rejection from it -- otherwise a target that rejects every DeregisterInstance call would
    # pass this check for the wrong reason.
    control_id = ctx.unique_name("sim2real-behav-sd-inst-control-")
    _register_instance(control_id)
    assert control_id in _instance_ids(), "positive-control instance missing from ListInstances after RegisterInstance"
    _deregister_instance(control_id)
    assert control_id not in _instance_ids(), "positive-control instance still listed after DeregisterInstance"

    # Break: an InstanceId that was never registered under this Service.
    never_registered_id = ctx.unique_name("sim2real-behav-sd-inst-never-")
    service_arn = sd.get_service(Id=service_id)["Service"]["Arn"]
    code, message = _error(
        lambda: sd.deregister_instance(ServiceId=service_id, InstanceId=never_registered_id)
    )
    assert code == "InstanceNotFound", f"expected InstanceNotFound, got {code}"
    expected = f"instanceId {never_registered_id} doesn't exists for service {service_arn}"
    assert message == expected, f"expected {expected!r}, got {message!r}"
    assert never_registered_id not in _instance_ids(), "never-registered id unexpectedly present in ListInstances"

    # Restore: the identical InstanceId, once actually registered, deregisters cleanly -- so the
    # rejection above was about absence, not the id string itself.
    _register_instance(never_registered_id)
    assert never_registered_id in _instance_ids(), "restored instance missing from ListInstances after RegisterInstance"
    _deregister_instance(never_registered_id)
    assert never_registered_id not in _instance_ids(), "restored instance still listed after DeregisterInstance"

    # An independent read for the now-deregistered id returns the specific not-found code.
    # (DeregisterInstance on an already-removed instance succeeds, so the not-found is
    # asserted via GetInstance rather than a repeat delete.)
    code, message = _error(
        lambda: sd.get_instance(ServiceId=service_id, InstanceId=never_registered_id)
    )
    assert code == "InstanceNotFound", f"expected InstanceNotFound from GetInstance, got {code}"
    assert message == never_registered_id, f"expected the message to name {never_registered_id!r}, got {message!r}"

    sd.delete_service(Id=service_id)
    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
