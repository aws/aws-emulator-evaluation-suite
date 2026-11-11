"""discover-instances-revision-increments."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "discover-instances-revision-increments"
GROUP = 'discover-instances'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DiscoverInstancesRevision must increase whenever the instance set backing a namespace/service changes."""

    sd = ctx.client("servicediscovery")

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
        ctx.on_cleanup(lambda: _delete_namespace(namespace_id))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(Name=name, NamespaceId=namespace_id, **kwargs)["Service"]["Id"]
        ctx.on_cleanup(lambda: sd.delete_service(Id=service_id))
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

    ns_name = ctx.unique_name("sim2real-behav-sd-ns-rev-")
    namespace_id = _create_http_namespace(ns_name)
    svc_name = ctx.unique_name("sim2real-behav-sd-svc-rev-")
    service_id = _create_service(svc_name, namespace_id)

    def revision():
        return sd.discover_instances_revision(
            NamespaceName=ns_name, ServiceName=svc_name
        )["InstancesRevision"]

    # Freeze detector: plain reads with no intervening mutation must not advance the revision.
    frozen = [revision() for _ in range(3)]
    assert len(set(frozen)) == 1, f"InstancesRevision must not change on reads alone, got {frozen!r}"
    rev_before = frozen[-1]

    instance_id = ctx.unique_name("sim2real-behav-sd-inst-rev-")
    _register_instance(service_id, instance_id, {"k": "v"})

    rev_after_register = _poll_until(revision, lambda r: r > rev_before, timeout_s=30, interval_s=2)
    assert rev_after_register > rev_before, "InstancesRevision must increase after a registration"

    _deregister_instance(service_id, instance_id)

    rev_after_deregister = _poll_until(
        revision, lambda r: r > rev_after_register, timeout_s=30, interval_s=2
    )
    assert rev_after_deregister > rev_after_register, (
        "InstancesRevision must increase after a deregistration"
    )

    sd.delete_service(Id=service_id)
    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
