"""mutate-deleted-service-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mutate-deleted-service-rejected"
GROUP = 'overly-permissive'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """[Overly-permissive guard] After DeleteService, WRITE operations against that ServiceId MUST fail
    with ServiceNotFound -- a deleted service must not be resurrectable by a mutation."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        """Call fn(); return the botocore Error.Code and Message if a ClientError is raised. An
        unexpected SUCCESS raises, because a target accepting a call real AWS rejects is the strongest
        signal available."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
        raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

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
        resp = sd.create_http_namespace(Name=name, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: _delete_namespace(namespace_id), "NamespaceNotFound"))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service = sd.create_service(Name=name, NamespaceId=namespace_id, **kwargs)["Service"]
        service_id = service["Id"]
        ctx.on_cleanup(lambda: _unless_gone(lambda: sd.delete_service(Id=service_id), "ServiceNotFound"))
        return service_id, service["Arn"]

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-updsvc-"))
    service_id, service_arn = _create_service(ctx.unique_name("sim2real-behav-sd-svc-updsvc-"), namespace_id)

    sd.delete_service(Id=service_id)

    # Independent read: the service must be gone via a different operation than any of the mutation
    # probes below, before those probes are asked to prove anything about it.
    gone_code, gone_message = _error(lambda: sd.get_service(Id=service_id))
    assert gone_code == "ServiceNotFound", f"expected ServiceNotFound from GetService, got {gone_code!r}"
    assert gone_message == "", f"expected GetService's ServiceNotFound to carry an empty message, got {gone_message!r}"

    upd_code, upd_message = _error(
        lambda: sd.update_service(Id=service_id, Service={"Description": "resurrect-me"})
    )
    assert upd_code == "ServiceNotFound", (
        f"UpdateService on a deleted service must fail ServiceNotFound, got {upd_code}"
    )
    assert upd_message == service_arn, f"expected the message to name {service_arn!r}, got {upd_message!r}"

    reg_code, reg_message = _error(
        lambda: sd.register_instance(
            ServiceId=service_id,
            InstanceId=ctx.unique_name("sim2real-behav-sd-inst-zombie-"),
            Attributes={"k": "v"},
        )
    )
    assert reg_code == "ServiceNotFound", (
        f"RegisterInstance on a deleted service must fail ServiceNotFound, got {reg_code}"
    )
    assert reg_message == service_arn, f"expected the message to name {service_arn!r}, got {reg_message!r}"

    attr_code, attr_message = _error(
        lambda: sd.update_service_attributes(ServiceId=service_id, Attributes={"k": "v"})
    )
    assert attr_code == "ServiceNotFound", (
        f"UpdateServiceAttributes on a deleted service must fail ServiceNotFound, got {attr_code}"
    )
    assert attr_message == "", (
        f"expected UpdateServiceAttributes' ServiceNotFound to carry an empty message, got {attr_message!r}"
    )

    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
