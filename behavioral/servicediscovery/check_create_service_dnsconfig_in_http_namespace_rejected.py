"""create-service-dnsconfig-in-http-namespace-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-service-dnsconfig-in-http-namespace-rejected"
GROUP = 'overly-permissive'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService with a DnsConfig in an HTTP namespace is refused with InvalidInput and its exact
    message and creates no service; without DnsConfig the service is created in that namespace, and
    after deletion GetService answers ServiceNotFound."""

    sd = ctx.client("servicediscovery")

    def _error(fn):
        """Call fn(); return its botocore error (Code and Message). A success raises."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {})
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

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
        def _delete_namespace_if_present():
            try:
                _delete_namespace(namespace_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NamespaceNotFound":
                    raise

        ctx.on_cleanup(_delete_namespace_if_present)
        return namespace_id

    namespace_id = _create_http_namespace(ctx.unique_name("sim2real-behav-sd-ns-req-"))

    bad_svc_name = ctx.unique_name("sim2real-behav-sd-svc-req-")
    error = _error(
        lambda: sd.create_service(
            Name=bad_svc_name,
            NamespaceId=namespace_id,
            DnsConfig={"NamespaceId": namespace_id, "DnsRecords": [{"Type": "A", "TTL": 60}]},
        )
    )
    code, message = error.get("Code"), error.get("Message")
    assert code == "InvalidInput", (
        f"DnsConfig on an HTTP-namespace service must be rejected with InvalidInput, got {code}"
    )
    expected_message = (
        "When you create a service using a namespace that has a type of HTTP, you can't include a "
        "DnsConfig element."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected CreateService must not have left a service behind.
    services = sd.list_services(
        Filters=[{"Name": "NAMESPACE_ID", "Values": [namespace_id], "Condition": "EQ"}]
    )["Services"]
    assert bad_svc_name not in [s["Name"] for s in services], (
        f"rejected CreateService must not create a service, found {services}"
    )

    # Positive control: the same namespace accepts CreateService when DnsConfig is
    # omitted, proving the target rejects the DnsConfig element specifically and is
    # not simply rejecting every CreateService call against an HTTP namespace.
    good_svc_name = ctx.unique_name("sim2real-behav-sd-svc-ok-")
    good_service_id = sd.create_service(Name=good_svc_name, NamespaceId=namespace_id)["Service"]["Id"]
    def _delete_service_if_present():
        try:
            sd.delete_service(Id=good_service_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ServiceNotFound":
                raise

    ctx.on_cleanup(_delete_service_if_present)

    got = sd.get_service(Id=good_service_id)["Service"]
    assert got["Name"] == good_svc_name, f"expected {good_svc_name}, got {got.get('Name')}"
    assert got["NamespaceId"] == namespace_id, f"expected {namespace_id}, got {got.get('NamespaceId')}"

    sd.delete_service(Id=good_service_id)
    error = _error(lambda: sd.get_service(Id=good_service_id))
    code, message = error.get("Code"), error.get("Message")
    assert code == "ServiceNotFound", f"expected ServiceNotFound after delete, got {code}"
    # GetService on a deleted service id returns ServiceNotFound with an empty message.
    expected_message = ""
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    _delete_namespace(namespace_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
