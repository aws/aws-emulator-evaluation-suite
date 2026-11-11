"""register-deregister-instance-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-deregister-instance-lifecycle"
GROUP = 'instance-lifecycle'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterInstance's async op reaches SUCCESS, the instance becomes visible via GetInstance/ListInstances, and DeregisterInstance removes it."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        # An unexpected success raises: accepting what AWS refuses must not read as a code mismatch.
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

    def _tolerate_gone(fn):
        # Teardown: the body may already have deleted the resource.
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NamespaceNotFound", "ServiceNotFound"):
                raise

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

    def _create_http_namespace(name, **kwargs):
        resp = sd.create_http_namespace(Name=name, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _tolerate_gone(lambda: _delete_namespace(namespace_id)))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(Name=name, NamespaceId=namespace_id, **kwargs)["Service"]["Id"]
        ctx.on_cleanup(lambda: _tolerate_gone(lambda: sd.delete_service(Id=service_id)))
        return service_id

    def _register_instance(service_id, instance_id, attributes, **kwargs):
        resp = sd.register_instance(
            ServiceId=service_id, InstanceId=instance_id, Attributes=attributes, **kwargs
        )

        def _drop_instance(service_id=service_id, instance_id=instance_id):
            try:
                r = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
                _wait_for_operation(r["OperationId"], timeout_s=30)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("InstanceNotFound", "ServiceNotFound"):
                    raise

        ctx.on_cleanup(_drop_instance)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"RegisterInstance failed: {op}")
        return op

    def _deregister_instance(service_id, instance_id, wait=True):
        resp = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
        if wait:
            return _wait_for_operation(resp["OperationId"])
        return resp

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-inst-"))
    service_id = _create_service(ctx.unique_name("sim2real-behav-sd-svc-inst-"), namespace_id)
    instance_id = ctx.unique_name("sim2real-behav-sd-inst-")

    _register_instance(service_id, instance_id, {"AWS_INSTANCE_IPV4": "10.0.0.5", "port": "8080"})

    got = sd.get_instance(ServiceId=service_id, InstanceId=instance_id)["Instance"]
    assert got["Id"] == instance_id, f"expected instance id {instance_id!r}, got {got['Id']!r}"
    assert got["Attributes"]["AWS_INSTANCE_IPV4"] == "10.0.0.5", (
        f"expected AWS_INSTANCE_IPV4 10.0.0.5, got {got['Attributes'].get('AWS_INSTANCE_IPV4')!r}"
    )

    listed = sd.list_instances(ServiceId=service_id)["Instances"]
    assert any(i["Id"] == instance_id for i in listed), "registered instance must appear in ListInstances"

    _deregister_instance(service_id, instance_id)
    code, message = _error(lambda: sd.get_instance(ServiceId=service_id, InstanceId=instance_id))
    assert code == "InstanceNotFound", f"expected InstanceNotFound after deregister, got {code}"
    assert message == instance_id, f"unexpected InstanceNotFound message: {message!r}"

    # DeregisterInstance on an already-deregistered instance id is idempotent: it reaches SUCCESS
    # rather than raising InstanceNotFound (that error is reserved for an id never registered at all
    # under this service).
    redereg_op = _deregister_instance(service_id, instance_id)
    assert redereg_op["Status"] == "SUCCESS", (
        f"expected idempotent re-deregister of an already-gone instance to reach SUCCESS, got {redereg_op}"
    )

    # The instance id is reusable once it is gone.
    _register_instance(service_id, instance_id, {"AWS_INSTANCE_IPV4": "10.0.0.6", "port": "8081"})
    got_again = sd.get_instance(ServiceId=service_id, InstanceId=instance_id)["Instance"]
    assert got_again["Attributes"]["AWS_INSTANCE_IPV4"] == "10.0.0.6", (
        f"expected re-registered instance to carry its new attributes, got {got_again['Attributes']!r}"
    )

    _deregister_instance(service_id, instance_id)
    code, message = _error(lambda: sd.get_instance(ServiceId=service_id, InstanceId=instance_id))
    assert code == "InstanceNotFound", f"expected InstanceNotFound after re-deregister, got {code}"
    assert message == instance_id, f"unexpected InstanceNotFound message: {message!r}"

    sd.delete_service(Id=service_id)
    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
