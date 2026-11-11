"""register-instance-missing-required-attribute-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-instance-missing-required-attribute-rejected"
GROUP = "negative-classes"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterInstance against a service whose DnsConfig defines an A record is
    rejected as InvalidInput when AWS_INSTANCE_IPV4 is omitted, and no instance is
    created; the same call with AWS_INSTANCE_IPV4 present succeeds."""
    sd = ctx.client("servicediscovery")
    name = f"{ctx.unique_name('sim2real-pubns-')}.com"

    tag_spec = [{"Key": "sim2real-check", "Value": CHECK}]

    create_op_id = sd.create_public_dns_namespace(Name=name, Tags=tag_spec)["OperationId"]
    op = _poll_operation(ctx, sd, create_op_id, timeout_s=180.0)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(sd, ns_id))

    svc = sd.create_service(
        Name=ctx.unique_name("sim2real-svc-"),
        NamespaceId=ns_id,
        DnsConfig={"DnsRecords": [{"Type": "A", "TTL": 60}], "RoutingPolicy": "WEIGHTED"},
        Tags=tag_spec,
    )["Service"]
    svc_id = svc["Id"]
    ctx.on_cleanup(lambda: _safe_delete_service(sd, svc_id))

    bad_instance_id = ctx.unique_name("sim2real-inst-bad-")
    error = _client_error(
        lambda: sd.register_instance(
            ServiceId=svc_id, InstanceId=bad_instance_id, Attributes={"unrelated": "x"}
        )
    )
    assert error.get("Code") == "InvalidInput", f"expected InvalidInput, got {error}"
    assert error.get("Message") == "Required attribute(s) AWS_INSTANCE_IPV4 are missing.", (
        f"unexpected InvalidInput message: {error.get('Message')!r}"
    )

    # Effect absent: the rejected instance was never registered.
    not_found = _client_error(
        lambda: sd.get_instance(ServiceId=svc_id, InstanceId=bad_instance_id)
    )
    assert not_found.get("Code") == "InstanceNotFound", (
        f"rejected instance should not exist, but GetInstance returned {not_found}"
    )
    assert not_found.get("Message") == bad_instance_id, (
        f"expected InstanceNotFound message {bad_instance_id!r}, got {not_found.get('Message')!r}"
    )

    # Positive control: same service, same shape, but with the required A-record
    # attribute present.
    good_instance_id = ctx.unique_name("sim2real-inst-good-")
    reg_op_id = sd.register_instance(
        ServiceId=svc_id,
        InstanceId=good_instance_id,
        Attributes={"AWS_INSTANCE_IPV4": "10.0.0.5"},
    )["OperationId"]
    ctx.on_cleanup(lambda: _safe_deregister(sd, svc_id, good_instance_id))
    reg_op = _poll_operation(ctx, sd, reg_op_id, timeout_s=120.0)
    assert reg_op["Status"] == "SUCCESS", f"register failed: {reg_op.get('ErrorMessage')}"
    instance = sd.get_instance(ServiceId=svc_id, InstanceId=good_instance_id)["Instance"]
    assert instance["Attributes"]["AWS_INSTANCE_IPV4"] == "10.0.0.5", (
        f"expected AWS_INSTANCE_IPV4=10.0.0.5, got {instance['Attributes']}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_operation(ctx, sd, operation_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(
        f"operation {operation_id} did not reach a terminal state within {timeout_s}s "
        f"(last status={op['Status'] if op else None})"
    )


def _safe_delete_namespace(sd, ns_id):
    try:
        sd.delete_namespace(Id=ns_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NamespaceNotFound":
            raise


def _safe_delete_service(sd, svc_id):
    try:
        sd.delete_service(Id=svc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ServiceNotFound":
            raise


def _safe_deregister(sd, svc_id, instance_id):
    try:
        sd.deregister_instance(ServiceId=svc_id, InstanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InstanceNotFound", "ServiceNotFound"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
