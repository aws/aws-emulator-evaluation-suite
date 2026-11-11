"""server-side-computed-health-status-from-route53."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-computed-health-status-from-route53"
GROUP = "server-side"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For a service with a Route 53 HealthCheckConfig, UpdateInstanceCustomHealthStatus is refused with
    CustomHealthNotFound and its exact message and GetInstancesHealthStatus converges on UNHEALTHY for
    the unreachable target; a custom-health service accepts the call and reads back UNHEALTHY."""
    sd = ctx.client("servicediscovery")
    registered: list[tuple[str, str]] = []
    ip = _unanswering_public_ip(ctx, lambda: _instances_gone(sd, registered))

    ns_resp = sd.create_http_namespace(Name=ctx.unique_name("sim2real-hcns-"))
    ns_op = _wait_operation(sd, ns_resp["OperationId"])
    ns_id = ns_op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _teardown_namespace(sd, ns_id))

    svc = sd.create_service(
        Name=ctx.unique_name("sim2real-hcsvc-"),
        NamespaceId=ns_id,
        Type="HTTP",
        HealthCheckConfig={"Type": "HTTP", "ResourcePath": "/", "FailureThreshold": 1},
    )["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: _teardown_service(sd, svc_id))

    instance_id = ctx.unique_name("sim2real-hcinst-")
    reg_resp = sd.register_instance(
        ServiceId=svc_id,
        InstanceId=instance_id,
        # A public address the check owns, so RegisterInstance's forbidden-range validation
        # (RFC 5737/1918/etc. are rejected) passes, with nothing behind it, so the Route 53
        # HTTP health checker never gets a response and converges on UNHEALTHY.
        Attributes={"AWS_INSTANCE_IPV4": ip, "AWS_INSTANCE_PORT": "54321"},
    )
    registered.append((svc_id, instance_id))
    _wait_operation(sd, reg_resp["OperationId"])
    ctx.on_cleanup(lambda: _teardown_instance(sd, svc_id, instance_id))

    error = _poll_until(
        lambda: _client_error(
            lambda: sd.update_instance_custom_health_status(
                ServiceId=svc_id, InstanceId=instance_id, Status="HEALTHY"
            )
        ),
        lambda e: e is not None and e.get("Code") not in ("ServiceNotFound", "InstanceNotFound"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert error.get("Code") == "CustomHealthNotFound", (
        f"expected CustomHealthNotFound (status isn't client-settable for a managed "
        f"health check), got {error!r}"
    )
    expected_message = f"'No Custom Health Check for instance '{instance_id}' in service '{svc['Arn']}''"
    assert error.get("Message") == expected_message, (
        f"expected CustomHealthNotFound message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: a same-shaped service that DOES carry HealthCheckCustomConfig
    # accepts the identical UpdateInstanceCustomHealthStatus call -- proving the
    # CustomHealthNotFound rejection above is specific to the managed HealthCheckConfig,
    # not a blanket failure of this account, these credentials or this API call.
    control_svc = sd.create_service(
        Name=ctx.unique_name("sim2real-hcctrlsvc-"),
        NamespaceId=ns_id,
        HealthCheckCustomConfig={"FailureThreshold": 1},
    )["Service"]
    control_svc_id = control_svc["Id"]
    ctx.on_cleanup(lambda: _teardown_service(sd, control_svc_id))

    control_instance_id = ctx.unique_name("sim2real-hcctrlinst-")
    control_reg_resp = sd.register_instance(
        ServiceId=control_svc_id,
        InstanceId=control_instance_id,
        Attributes={"custom": "v1"},
    )
    _wait_operation(sd, control_reg_resp["OperationId"])
    ctx.on_cleanup(lambda: _teardown_instance(sd, control_svc_id, control_instance_id))

    _poll_until(
        lambda: sd.update_instance_custom_health_status(
            ServiceId=control_svc_id, InstanceId=control_instance_id, Status="UNHEALTHY"
        )
        is not None,
        lambda accepted: accepted is True,
        timeout_s=60.0,
        interval_s=5.0,
    )
    control_status = _poll_until(
        lambda: sd.get_instances_health_status(ServiceId=control_svc_id, Instances=[control_instance_id])[
            "Status"
        ].get(control_instance_id),
        lambda s: s == "UNHEALTHY",
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert control_status == "UNHEALTHY", (
        f"positive control: a service WITH HealthCheckCustomConfig must accept "
        f"UpdateInstanceCustomHealthStatus and reflect it on an independent read, "
        f"got {control_status!r}"
    )

    status = _poll_until(
        lambda: sd.get_instances_health_status(ServiceId=svc_id, Instances=[instance_id])["Status"].get(
            instance_id
        ),
        lambda s: s == "UNHEALTHY",
        timeout_s=300.0,
        interval_s=15.0,
    )
    assert status == "UNHEALTHY", (
        f"expected the Route 53 health checker to independently drive the managed "
        f"instance's status to UNHEALTHY for an unreachable target, got {status!r}"
    )


def _unanswering_public_ip(ctx, dependents_gone):
    """An Elastic IP the check allocates and leaves unassociated, so no host answers on it.

    Its tags carry no sim2real mark, so only this check releases it, and it does so
    only once ``dependents_gone()`` proves every instance on it is deregistered, so a leaked
    health check never probes an address AWS hands to someone else; otherwise it stays allocated."""
    ec2 = ctx.client("ec2")
    eip = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "held-for", "Value": "cloud-map-health-check"}]}],
    )

    def release():
        dependents_gone()
        ec2.release_address(AllocationId=eip["AllocationId"])

    ctx.on_cleanup(release)
    return eip["PublicIp"]


def _instances_gone(sd, registered):
    """Raise unless GetInstance answers InstanceNotFound or ServiceNotFound for every instance."""
    for service_id, instance_id in registered:
        try:
            sd.get_instance(ServiceId=service_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("InstanceNotFound", "ServiceNotFound"):
                continue
            raise
        raise AssertionError(f"instance {instance_id} is still registered; its Elastic IP stays allocated")


def _wait_operation(sd, operation_id, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            break
        time.sleep(interval_s)
    if op is None or op["Status"] != "SUCCESS":
        raise AssertionError(f"operation {operation_id} did not reach SUCCESS: {op}")
    return op


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so an emulator
    accepting a call real AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _teardown_instance(sd, service_id, instance_id):
    try:
        op_id = sd.deregister_instance(ServiceId=service_id, InstanceId=instance_id)["OperationId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("InstanceNotFound", "ServiceNotFound"):
            return
        raise
    _wait_operation(sd, op_id)


def _retry_in_use(fn, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _teardown_service(sd, service_id):
    try:
        _retry_in_use(lambda: sd.delete_service(Id=service_id))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ServiceNotFound":
            raise


def _teardown_namespace(sd, namespace_id):
    try:
        op_id = _retry_in_use(lambda: sd.delete_namespace(Id=namespace_id))["OperationId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NamespaceNotFound":
            raise
        return
    _wait_operation(sd, op_id)


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError:  # InstanceNotFound while propagating; keep polling
            last = None
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
