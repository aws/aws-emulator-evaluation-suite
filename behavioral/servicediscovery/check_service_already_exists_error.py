"""service-already-exists-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-already-exists-error"
GROUP = 'service-lifecycle'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second Service with the same Name in the same namespace must fail with
    ServiceAlreadyExists, the name must stay bound to exactly the original service, and
    deleting that original service must free the name for a fresh CreateService."""

    sd = ctx.client("servicediscovery")
    tags_kwarg = {"Tags": [{"Key": "sim2real-check", "Value": CHECK}]}

    def _client_error(fn):
        try:
            fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") is None:
                raise
            return error
        raise AssertionError("expected the call to fail, but it succeeded")

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
        resp = sd.create_http_namespace(Name=name, **tags_kwarg, **kwargs)
        op = _wait_for_operation(resp["OperationId"])
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"CreateHttpNamespace failed: {op}")
        namespace_id = op["Targets"]["NAMESPACE"]
        ctx.on_cleanup(lambda: _delete_namespace(namespace_id))
        return namespace_id

    def _safe_delete_service(service_id):
        try:
            sd.delete_service(Id=service_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ServiceNotFound":
                raise

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(Name=name, NamespaceId=namespace_id, **tags_kwarg, **kwargs)["Service"]["Id"]
        ctx.on_cleanup(lambda: _safe_delete_service(service_id))
        return service_id

    def _services_named(namespace_id, name):
        matches = sd.list_services(
            Filters=[{"Name": "NAMESPACE_ID", "Values": [namespace_id], "Condition": "EQ"}]
        )["Services"]
        return [s for s in matches if s["Name"] == name]

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-svcdup-"))
    svc_name = ctx.unique_name("sim2real-behav-sd-svc-dup-")
    original_id = _create_service(svc_name, namespace_id)

    error = _client_error(lambda: sd.create_service(Name=svc_name, NamespaceId=namespace_id))
    assert error.get("Code") == "ServiceAlreadyExists", f"expected ServiceAlreadyExists, got {error}"
    assert error.get("Message") == "Service already exists.", (
        f"unexpected ServiceAlreadyExists message: {error.get('Message')!r}"
    )

    # independent read at the destination: the rejected call must not have created a
    # second service, and the name must still resolve to the original one.
    same_name = _services_named(namespace_id, svc_name)
    assert len(same_name) == 1, f"expected exactly one live service named {svc_name!r}, got {same_name}"
    assert same_name[0]["Id"] == original_id, (
        f"expected the surviving service to be the original {original_id}, got {same_name[0]['Id']}"
    )

    # restore: the conflict is state (an existing service owns the name), not the input
    # itself — deleting that state must free the name for an identical CreateService.
    sd.delete_service(Id=original_id)
    after_delete = _services_named(namespace_id, svc_name)
    assert not after_delete, f"expected {svc_name!r} gone after deleting {original_id}, got {after_delete}"

    restored_id = _create_service(svc_name, namespace_id)
    # Measured, not assumed: Cloud Map hands the recreated Name/NamespaceId pair back
    # its original Service Id rather than minting a new one.
    assert restored_id == original_id, (
        f"expected the recreated service to reuse id {original_id}, got {restored_id}"
    )
    restored = _services_named(namespace_id, svc_name)
    assert len(restored) == 1 and restored[0]["Id"] == restored_id, (
        f"expected {svc_name!r} to resolve to the restored service {restored_id}, got {restored}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
