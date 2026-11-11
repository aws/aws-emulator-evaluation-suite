"""discover-instances-end-to-end."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "discover-instances-end-to-end"
GROUP = 'discover-instances'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DiscoverInstances returns registered instances with their attributes, and stops returning them after deregistration."""

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

    ns_name = ctx.unique_name("sim2real-behav-sd-ns-disc-")
    namespace_id = _create_http_namespace(ns_name)
    svc_name = ctx.unique_name("sim2real-behav-sd-svc-disc-")
    service_id = _create_service(svc_name, namespace_id)

    inst_a = ctx.unique_name("sim2real-behav-sd-inst-a-")
    inst_b = ctx.unique_name("sim2real-behav-sd-inst-b-")
    _register_instance(service_id, inst_a, {"custom": "alpha"})
    _register_instance(service_id, inst_b, {"custom": "beta"})

    def discover():
        return sd.discover_instances(NamespaceName=ns_name, ServiceName=svc_name)["Instances"]

    def has_both(instances):
        ids = {i["InstanceId"] for i in instances}
        return inst_a in ids and inst_b in ids

    found = _poll_until(discover, has_both, timeout_s=30, interval_s=2)
    by_id = {i["InstanceId"]: i for i in found}
    assert by_id[inst_a]["Attributes"]["custom"] == "alpha", (
        f"expected instance {inst_a} attribute custom=alpha, got {by_id[inst_a]['Attributes']!r}"
    )
    assert by_id[inst_b]["Attributes"]["custom"] == "beta", (
        f"expected instance {inst_b} attribute custom=beta, got {by_id[inst_b]['Attributes']!r}"
    )

    op_a = _deregister_instance(service_id, inst_a)
    assert op_a["Status"] == "SUCCESS", f"DeregisterInstance({inst_a}) failed: {op_a}"

    def only_b_left(instances):
        ids = {i["InstanceId"] for i in instances}
        return inst_a not in ids and inst_b in ids

    _poll_until(discover, only_b_left, timeout_s=30, interval_s=2)

    op_b = _deregister_instance(service_id, inst_b)
    assert op_b["Status"] == "SUCCESS", f"DeregisterInstance({inst_b}) failed: {op_b}"
    sd.delete_service(Id=service_id)
    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
