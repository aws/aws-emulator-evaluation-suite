"""e2e-service-discovery-full-lifecycle-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-service-discovery-full-lifecycle-flow"
GROUP = "e2e"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Register makes an instance discoverable, deregister makes it disappear, and delete succeeds only once the child resource is gone."""
    sd = ctx.client("servicediscovery")

    ns_name = ctx.unique_name("simparity-sd-e2e-")
    ns_resp = sd.create_http_namespace(Name=ns_name)
    ns_op = _wait_operation(sd, ns_resp["OperationId"])
    ns_id = ns_op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace_best_effort(sd, ns_id))

    svc_name = ctx.unique_name("simparity-sd-e2e-svc-")
    svc = sd.create_service(Name=svc_name, NamespaceId=ns_id)["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: _delete_service_best_effort(sd, svc_id))

    instance_id = ctx.unique_name("simparity-sd-e2e-inst-")
    reg_resp = sd.register_instance(
        ServiceId=svc_id, InstanceId=instance_id, Attributes={"CUSTOM_KEY": "v1"}
    )
    _wait_operation(sd, reg_resp["OperationId"], timeout_s=120.0)
    ctx.on_cleanup(lambda: _deregister_instance_best_effort(sd, svc_id, instance_id))

    found = _poll_discover_instances(sd, ns_name, svc_name, instance_id, expect_present=True)
    assert found["Attributes"]["CUSTOM_KEY"] == "v1", (
        f"expected CUSTOM_KEY='v1' on the discovered instance, got {found['Attributes']!r}"
    )

    # DeleteService must be blocked while the instance is still registered.
    delete_blocked_code, delete_blocked_message = _error(lambda: sd.delete_service(Id=svc_id))
    assert delete_blocked_code == "ResourceInUse", (
        f"expected ResourceInUse deleting a service with a registered instance, got {delete_blocked_code!r}"
    )
    assert delete_blocked_message == "Service contains registered instances; delete the instances before deleting the service", f"unexpected ResourceInUse message: {delete_blocked_message!r}"
    still_svc = sd.get_service(Id=svc_id)["Service"]
    assert still_svc["Id"] == svc_id, "service must still exist after the blocked delete"

    dereg_resp = sd.deregister_instance(ServiceId=svc_id, InstanceId=instance_id)
    _wait_operation(sd, dereg_resp["OperationId"], timeout_s=120.0)

    _poll_discover_instances(sd, ns_name, svc_name, instance_id, expect_present=False)

    # DeleteNamespace must be blocked while the service is still associated with it.
    ns_delete_blocked_code, ns_delete_blocked_message = _error(lambda: sd.delete_namespace(Id=ns_id))
    assert ns_delete_blocked_code == "ResourceInUse", (
        f"expected ResourceInUse deleting a namespace with an associated service, got {ns_delete_blocked_code!r}"
    )
    assert ns_delete_blocked_message == "Namespace has associated services; delete the services before deleting the namespace", f"unexpected ResourceInUse message: {ns_delete_blocked_message!r}"
    still_ns = sd.get_namespace(Id=ns_id)["Namespace"]
    assert still_ns["Id"] == ns_id, "namespace must still exist after the blocked delete"

    sd.delete_service(Id=svc_id)

    list_resp = sd.list_services(Filters=[{"Name": "NAMESPACE_ID", "Values": [ns_id]}])
    assert list_resp["Services"] == [], "service still listed under the namespace after DeleteService"

    reg_after_delete_code, reg_after_delete_message = _error(
        lambda: sd.register_instance(
            ServiceId=svc_id,
            InstanceId=ctx.unique_name("simparity-sd-e2e-postdel-"),
            Attributes={"CUSTOM_KEY": "v2"},
        )
    )
    assert reg_after_delete_code == "ServiceNotFound", (
        f"expected ServiceNotFound registering against a deleted service, got {reg_after_delete_code!r}"
    )
    assert reg_after_delete_message == f"arn:aws:servicediscovery:{ctx.region}:{ctx.account}:service/{svc_id}", f"unexpected ServiceNotFound message: {reg_after_delete_message!r}"

    ns_delete_resp = sd.delete_namespace(Id=ns_id)
    _wait_operation(sd, ns_delete_resp["OperationId"], timeout_s=180.0)

    create_after_delete_code, create_after_delete_message = _error(
        lambda: sd.create_service(Name=ctx.unique_name("simparity-sd-e2e-postdel-ns-"), NamespaceId=ns_id)
    )
    assert create_after_delete_code == "NamespaceNotFound", (
        f"expected NamespaceNotFound creating a service against a deleted namespace, got {create_after_delete_code!r}"
    )
    assert create_after_delete_message == ns_id, f"unexpected NamespaceNotFound message: {create_after_delete_message!r}"

    get_code, get_message = _error(lambda: sd.get_namespace(Id=ns_id))
    assert get_code == "NamespaceNotFound", (
        f"expected NamespaceNotFound reading a deleted namespace, got {get_code!r}"
    )
    assert get_message == "", f"unexpected NamespaceNotFound message: {get_message!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_operation(sd, operation_id, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        status = op["Status"]
        if status == "SUCCESS":
            return op
        if status == "FAIL":
            raise AssertionError(
                f"operation {operation_id} failed: {op.get('ErrorCode')} {op.get('ErrorMessage')}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"operation {operation_id} stuck in {status} after {timeout_s}s")
        time.sleep(interval_s)


def _poll_discover_instances(
    sd, ns_name, svc_name, instance_id, expect_present, timeout_s: float = 60.0, interval_s: float = 3.0
):
    deadline = time.monotonic() + timeout_s
    while True:
        resp = sd.discover_instances(NamespaceName=ns_name, ServiceName=svc_name)
        match = next((i for i in resp["Instances"] if i["InstanceId"] == instance_id), None)
        if expect_present and match is not None:
            return match
        if not expect_present and match is None:
            return None
        if time.monotonic() >= deadline:
            if expect_present:
                raise AssertionError(f"instance {instance_id} never appeared in DiscoverInstances within {timeout_s}s")
            raise AssertionError(f"instance {instance_id} still appears in DiscoverInstances after {timeout_s}s")
        time.sleep(interval_s)


def _delete_namespace_best_effort(sd, namespace_id):
    from botocore.exceptions import ClientError

    try:
        op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
        _wait_operation(sd, op_id, timeout_s=180.0)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NamespaceNotFound":
            raise


def _delete_service_best_effort(sd, service_id):
    from botocore.exceptions import ClientError

    try:
        sd.delete_service(Id=service_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ServiceNotFound":
            raise


def _deregister_instance_best_effort(sd, service_id, instance_id):
    from botocore.exceptions import ClientError

    try:
        op_id = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
        _wait_operation(sd, op_id, timeout_s=120.0)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InstanceNotFound", "ServiceNotFound"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
