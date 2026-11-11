"""discover-instances-namespace-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "discover-instances-namespace-not-found"
GROUP = 'discover-instances'
SERVICES = ['servicediscovery']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DiscoverInstances against a NamespaceName that doesn't exist must fail with NamespaceNotFound,
    while the identical call against a namespace/service this check creates must succeed — otherwise
    the negative is indistinguishable from a target that rejects every DiscoverInstances call."""

    sd = ctx.client("servicediscovery")

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.5, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _wait_for_operation(operation_id, timeout_s=60, interval_s=1.5):
        op = _poll_until(
            lambda: sd.get_operation(OperationId=operation_id)["Operation"],
            lambda o: o.get("Status") in ("SUCCESS", "FAIL"),
            timeout_s=timeout_s, interval_s=interval_s,
            description=f"GetOperation({operation_id})",
        )
        if op["Status"] != "SUCCESS":
            raise RuntimeError(f"operation {operation_id} did not succeed: {op}")
        return op

    def _error(fn):
        """An unexpected SUCCESS raises, because a target that accepts what real AWS refuses is the
        strongest signal available."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
        raise AssertionError(f"expected NamespaceNotFound, but the call SUCCEEDED and returned {result!r}")

    ns_name = ctx.unique_name("sim2real-behav-sd-ns-disc404-")
    create_op = sd.create_http_namespace(Name=ns_name)
    namespace_id = _wait_for_operation(create_op["OperationId"])["Targets"]["NAMESPACE"]

    def _delete_namespace():
        resp = sd.delete_namespace(Id=namespace_id)
        _wait_for_operation(resp["OperationId"])

    ctx.on_cleanup(_delete_namespace)

    svc_name = ctx.unique_name("sim2real-behav-sd-svc-disc404-")
    service_id = sd.create_service(Name=svc_name, NamespaceId=namespace_id)["Service"]["Id"]
    ctx.on_cleanup(lambda: sd.delete_service(Id=service_id))

    # Positive control: DiscoverInstances against the namespace/service this check just created
    # must succeed, proving the account and credentials can otherwise perform this call before the
    # negative case below is trusted.
    positive = sd.discover_instances(NamespaceName=ns_name, ServiceName=svc_name)
    assert positive["Instances"] == [], f"expected no instances yet, got {positive['Instances']!r}"

    code, message = _error(
        lambda: sd.discover_instances(
            NamespaceName=ctx.unique_name("sim2real-behav-sd-ns-missing-"), ServiceName="whatever"
        )
    )
    assert code == "NamespaceNotFound", f"expected NamespaceNotFound, got {code}"
    assert message == "", f"expected DiscoverInstances' NamespaceNotFound to carry an empty message, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
