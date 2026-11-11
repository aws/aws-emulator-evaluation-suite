"""delete-service-in-use-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-service-in-use-conflict"
GROUP = 'overly-permissive'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[Overly-permissive guard] DeleteService MUST fail with ResourceInUse while a registered Instance still exists."""

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

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-svcinuse-"))
    service_id = _create_service(ctx.unique_name("sim2real-behav-sd-svc-inuse-"), namespace_id)
    instance_id = ctx.unique_name("sim2real-behav-sd-inst-")
    _register_instance(service_id, instance_id, {"custom-key": "custom-value"})

    code, message = _error(lambda: sd.delete_service(Id=service_id))
    assert code == "ResourceInUse", f"service delete with registered instance should fail ResourceInUse, got {code}"
    assert message == "Service contains registered instances; delete the instances before deleting the service", f"unexpected ResourceInUse message: {message!r}"

    still_there = sd.get_service(Id=service_id)["Service"]
    assert still_there["Id"] == service_id, (
        f"service should still exist after the rejected delete, got {still_there}"
    )

    _deregister_instance(service_id, instance_id)
    sd.delete_service(Id=service_id)

    gone_code, gone_message = _error(lambda: sd.get_service(Id=service_id))
    assert gone_code == "ServiceNotFound", f"service should be gone after delete, got {gone_code}"
    assert gone_message == "", f"unexpected GetService message: {gone_message!r}"

    mutate_code, mutate_message = _error(
        lambda: sd.register_instance(
            ServiceId=service_id,
            InstanceId=ctx.unique_name("sim2real-behav-sd-inst-zombie-"),
            Attributes={"k": "v"},
        )
    )
    assert mutate_code == "ServiceNotFound", (
        f"RegisterInstance on the deleted service must fail ServiceNotFound, got {mutate_code}"
    )
    assert mutate_message == f"arn:aws:servicediscovery:{ctx.region}:{ctx.account}:service/{service_id}", (
        f"unexpected RegisterInstance message: {mutate_message!r}"
    )

    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
