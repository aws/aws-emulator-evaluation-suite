"""concurrent-register-same-instance-id."""
from __future__ import annotations

import time

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-register-same-instance-id"
GROUP = 'concurrency'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing RegisterInstance calls for the SAME InstanceId must resolve consistently: every accepted call's
    async op terminates (SUCCESS or a well-defined conflict error), and the final GetInstance state matches
    exactly one of the submitted attribute sets (no interleaved/partial-write corruption)."""

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

    def _absent_ok(fn, *codes):
        # Cleanup for a resource the body may already have deleted.
        def _run():
            try:
                fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in codes:
                    raise
        return _run

    def _delete_namespace(namespace_id, wait=True):
        resp = sd.delete_namespace(Id=namespace_id)
        if wait:
            return _wait_for_operation(resp["OperationId"])
        return resp

    def _create_http_namespace(name, **kwargs):
        resp = sd.create_http_namespace(
            Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
        )
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(_absent_ok(lambda: _delete_namespace(namespace_id), "NamespaceNotFound"))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(
            Name=name, NamespaceId=namespace_id, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
        )["Service"]["Id"]
        ctx.on_cleanup(_absent_ok(lambda: sd.delete_service(Id=service_id), "ServiceNotFound"))
        return service_id

    def _deregister_instance(service_id, instance_id, wait=True):
        resp = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)
        if wait:
            return _wait_for_operation(resp["OperationId"])
        return resp

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-race-"))
    service_id = _create_service(ctx.unique_name("sim2real-behav-sd-svc-race-"), namespace_id)
    instance_id = ctx.unique_name("sim2real-behav-sd-inst-race-")

    n = 5
    attribute_sets = [{"racer": str(i)} for i in range(n)]

    # Registered before the race so a failure anywhere below still deregisters the instance
    # ahead of the service and namespace deletes (cleanups run last-in, first-out).
    ctx.on_cleanup(
        _absent_ok(
            lambda: _deregister_instance(service_id, instance_id), "InstanceNotFound", "ServiceNotFound"
        )
    )

    def register(i):
        resp = sd.register_instance(
            ServiceId=service_id, InstanceId=instance_id, Attributes=attribute_sets[i]
        )
        return _wait_for_operation(resp["OperationId"], timeout_s=90)

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(register, i) for i in range(n)]
        outcomes = []
        for f in futures:
            try:
                outcomes.append(("ok", f.result()))
            except ClientError as exc:
                outcomes.append(("err", exc.response))


    ops = [v for kind, v in outcomes if kind == "ok"]
    errors = [v for kind, v in outcomes if kind == "err"]
    error_codes = [e["Error"]["Code"] for e in errors]

    assert ops, f"at least one concurrent RegisterInstance must be accepted, errors={error_codes}"

    # Every accepted call's async operation must reach a terminal state.
    for op in ops:
        assert op["Status"] in ("SUCCESS", "FAIL"), f"op did not terminate: {op}"

    # Any rejection is DuplicateRequest pointing back at an in-flight registration.
    for error in errors:
        code, message = error["Error"]["Code"], error["Error"].get("Message")
        assert code == "DuplicateRequest", f"unexpected race error code: {code}"
        dup_op_id = error.get("DuplicateOperationId")
        assert dup_op_id in [op["Id"] for op in ops], (
            f"DuplicateOperationId {dup_op_id!r} names none of the accepted operations {[op['Id'] for op in ops]}"
        )
        expected_message = f"Another operation of type RegisterInstance and id {dup_op_id} is in progress"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Final state must be exactly one of the submitted attribute sets - no interleaved corruption.
    final = sd.get_instance(ServiceId=service_id, InstanceId=instance_id)["Instance"]
    assert final["Attributes"].get("racer") in [str(i) for i in range(n)], (
        f"racy registration produced a corrupted attribute set: {final['Attributes']}"
    )

    _deregister_instance(service_id, instance_id)

    # The teardown already deregisters -- prove it took effect via an independent read
    # rather than leaving the delete unasserted.
    try:
        sd.get_instance(ServiceId=service_id, InstanceId=instance_id)
        raise AssertionError("instance still visible via GetInstance after deregister SUCCESS")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "InstanceNotFound", f"expected InstanceNotFound after deregister, got {code}"

    sd.delete_service(Id=service_id)
    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
