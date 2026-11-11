"""service-attributes-crud."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-attributes-crud"
GROUP = 'service-attributes'
SERVICES = ['servicediscovery']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServiceAttributes/GetServiceAttributes/DeleteServiceAttributes form a consistent read-your-writes cycle."""

    sd = ctx.client("servicediscovery")

    def _client_error(fn):
        """Call fn(); return its botocore Error dict. An unexpected success raises."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {})
        raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")

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

    def _tolerating(not_found_code, fn):
        """Teardown for a resource the check may already have deleted."""
        def _run():
            try:
                fn()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != not_found_code:
                    raise
        return _run

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
        ctx.on_cleanup(_tolerating("NamespaceNotFound", lambda: _delete_namespace(namespace_id)))
        return namespace_id

    def _create_service(name, namespace_id, **kwargs):
        service_id = sd.create_service(Name=name, NamespaceId=namespace_id, **kwargs)["Service"]["Id"]
        ctx.on_cleanup(_tolerating("ServiceNotFound", lambda: sd.delete_service(Id=service_id)))
        return service_id

    tags_kv = [{"Key": "sim2real", "Value": "service-attributes-crud"}]
    namespace_id = _create_http_namespace(
        ctx.unique_name("sim2real-behav-sd-ns-attr-"), Tags=tags_kv
    )
    service_id = _create_service(
        ctx.unique_name("sim2real-behav-sd-svc-attr-"), namespace_id, Tags=tags_kv
    )

    sd.update_service_attributes(ServiceId=service_id, Attributes={"env": "prod", "tier": "gold"})
    got = sd.get_service_attributes(ServiceId=service_id)["ServiceAttributes"]
    assert got["Attributes"]["env"] == "prod", f"expected env=prod, got {got['Attributes'].get('env')!r}"
    assert got["Attributes"]["tier"] == "gold", f"expected tier=gold, got {got['Attributes'].get('tier')!r}"

    sd.delete_service_attributes(ServiceId=service_id, Attributes=["tier"])
    got2 = sd.get_service_attributes(ServiceId=service_id)["ServiceAttributes"]
    assert "tier" not in got2["Attributes"], "deleted attribute key must not reappear"
    assert got2["Attributes"]["env"] == "prod", "untouched attribute key must survive partial delete"

    sd.delete_service(Id=service_id)
    post_delete = _client_error(lambda: sd.get_service_attributes(ServiceId=service_id))
    assert post_delete.get("Code") == "ServiceNotFound", (
        f"GetServiceAttributes on a deleted service must fail ServiceNotFound, got {post_delete}"
    )
    assert post_delete.get("Message") == "", (
        f"expected an empty ServiceNotFound message, got {post_delete.get('Message')!r}"
    )

    _delete_namespace(namespace_id)
    post_delete_ns = _client_error(lambda: sd.get_namespace(Id=namespace_id))
    assert post_delete_ns.get("Code") == "NamespaceNotFound", (
        f"GetNamespace on a deleted namespace must fail NamespaceNotFound, got {post_delete_ns}"
    )
    assert post_delete_ns.get("Message") == "", (
        f"expected an empty NamespaceNotFound message, got {post_delete_ns.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
