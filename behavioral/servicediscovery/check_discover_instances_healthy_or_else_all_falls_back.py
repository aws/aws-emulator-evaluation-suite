"""discover-instances-healthy-or-else-all-falls-back."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "discover-instances-healthy-or-else-all-falls-back"
GROUP = "health-filtering"
SERVICES = ["servicediscovery"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _operation(sd, op_id: str) -> dict:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=op_id)["Operation"]
        if op["Status"] == "SUCCESS":
            return op
        assert op["Status"] != "FAIL", f"Cloud Map operation failed: {op.get('ErrorCode')!r} {op.get('ErrorMessage')!r}"
        time.sleep(2)
    raise AssertionError("Cloud Map operation did not reach SUCCESS within 120s")


def _delete_namespace(sd, ns_id: str) -> None:
    try:
        op_id = sd.delete_namespace(Id=ns_id)["OperationId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NamespaceNotFound":
            return
        raise
    _operation(sd, op_id)


def _delete_service(sd, svc_id: str) -> None:
    """Delete the service, retrying while a just-deregistered instance still holds it."""
    deadline = time.monotonic() + 45
    while True:
        try:
            sd.delete_service(Id=svc_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ServiceNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _deregister(sd, svc_id: str, inst: str) -> None:
    """Deregister and wait for the operation; DuplicateRequest means another operation on the
    instance is still in flight, so retry until it settles."""
    deadline = time.monotonic() + 45
    while True:
        try:
            op_id = sd.deregister_instance(ServiceId=svc_id, InstanceId=inst)["OperationId"]
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InstanceNotFound", "ServiceNotFound"):
                return
            if code != "DuplicateRequest" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    _operation(sd, op_id)


def _namespace_and_service(ctx, sd, **service_kwargs) -> tuple[str, str, str]:
    """An HTTP namespace and one service in it, both deleted at cleanup."""
    ns_name = ctx.unique_name("sim2real-behav-ns-")
    op = _operation(sd, sd.create_http_namespace(
        Name=ns_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["OperationId"])
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace(sd, ns_id))
    svc_name = ctx.unique_name("sim2real-behav-svc-")
    svc_id = sd.create_service(Name=svc_name, NamespaceId=ns_id,
                               Tags=[{"Key": "sim2real", "Value": CHECK}], **service_kwargs)["Service"]["Id"]
    ctx.on_cleanup(lambda: _delete_service(sd, svc_id))
    return ns_name, svc_name, svc_id


def _register(ctx, sd, svc_id: str, inst: str, attrs: dict) -> None:
    op_id = sd.register_instance(ServiceId=svc_id, InstanceId=inst,
                                 Attributes={"AWS_INSTANCE_IPV4": "192.0.2.10", **attrs})["OperationId"]
    ctx.on_cleanup(lambda: _deregister(sd, svc_id, inst))
    _operation(sd, op_id)


def _discover(sd, ns_name: str, svc_name: str, **kwargs) -> dict:
    resp = sd.discover_instances(NamespaceName=ns_name, ServiceName=svc_name, **kwargs)
    return {i["InstanceId"]: i.get("HealthStatus") for i in resp["Instances"]}


def _converge(observe, expected, *, budget_s: float = 150.0, what: str = "") -> None:
    """Poll ``observe()`` until it equals ``expected``; eventual consistency permits a stale read."""
    deadline = time.monotonic() + budget_s
    got = observe()
    while got != expected:
        if time.monotonic() > deadline:
            raise AssertionError(f"{what}: expected {expected!r}, still {got!r} after {budget_s}s")
        time.sleep(3)
        got = observe()


def _set_health(sd, svc_id: str, inst: str, status: str) -> None:
    """UpdateInstanceCustomHealthStatus, retrying while the health subsystem has not yet seen the
    new service or instance (it answers ServiceNotFound / InstanceNotFound until it has)."""
    deadline = time.monotonic() + 90
    while True:
        try:
            sd.update_instance_custom_health_status(ServiceId=svc_id, InstanceId=inst, Status=status)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ServiceNotFound", "InstanceNotFound") \
                    or time.monotonic() > deadline:
                raise
            time.sleep(3)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DiscoverInstances' HealthStatus filter: with every instance UNHEALTHY, HEALTHY finds nothing
    while HEALTHY_OR_ELSE_ALL returns all; once one is HEALTHY, HEALTHY and HEALTHY_OR_ELSE_ALL return
    just it, UNHEALTHY just the other, and ALL both with their status."""
    sd = ctx.client("servicediscovery")
    ns_name, svc_name, svc_id = _namespace_and_service(
        ctx, sd, HealthCheckCustomConfig={"FailureThreshold": 1})
    _register(ctx, sd, svc_id, "inst-a", {"role": "a"})
    _register(ctx, sd, svc_id, "inst-b", {"role": "b"})
    _converge(lambda: set(_discover(sd, ns_name, svc_name, HealthStatus="ALL")), {"inst-a", "inst-b"},
              what="both registered instances discoverable under ALL")

    _set_health(sd, svc_id, "inst-a", "UNHEALTHY")
    _set_health(sd, svc_id, "inst-b", "UNHEALTHY")
    both_bad = {"inst-a": "UNHEALTHY", "inst-b": "UNHEALTHY"}
    _converge(lambda: _discover(sd, ns_name, svc_name, HealthStatus="ALL"), both_bad,
              what="ALL with both instances unhealthy")
    _converge(lambda: _discover(sd, ns_name, svc_name, HealthStatus="HEALTHY"), {},
              what="HEALTHY with no healthy instance")
    _converge(lambda: _discover(sd, ns_name, svc_name, HealthStatus="UNHEALTHY"), both_bad,
              what="UNHEALTHY with both instances unhealthy")
    _converge(lambda: _discover(sd, ns_name, svc_name, HealthStatus="HEALTHY_OR_ELSE_ALL"), both_bad,
              what="HEALTHY_OR_ELSE_ALL falling back to every instance")

    _set_health(sd, svc_id, "inst-a", "HEALTHY")
    _converge(lambda: _discover(sd, ns_name, svc_name, HealthStatus="ALL"),
              {"inst-a": "HEALTHY", "inst-b": "UNHEALTHY"}, what="ALL with one healthy instance")
    _converge(lambda: _discover(sd, ns_name, svc_name, HealthStatus="HEALTHY_OR_ELSE_ALL"),
              {"inst-a": "HEALTHY"}, what="HEALTHY_OR_ELSE_ALL with one healthy instance")
    _converge(lambda: _discover(sd, ns_name, svc_name, HealthStatus="HEALTHY"),
              {"inst-a": "HEALTHY"}, what="HEALTHY with one healthy instance")
    _converge(lambda: _discover(sd, ns_name, svc_name, HealthStatus="UNHEALTHY"),
              {"inst-b": "UNHEALTHY"}, what="UNHEALTHY with one healthy instance")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
