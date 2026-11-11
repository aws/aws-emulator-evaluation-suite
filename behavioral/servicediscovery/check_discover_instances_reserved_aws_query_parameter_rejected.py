"""discover-instances-reserved-aws-query-parameter-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "discover-instances-reserved-aws-query-parameter-rejected"
GROUP = "attribute-filtering"
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


def _error(fn) -> tuple[str, str]:
    """The (code, message) fn raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DiscoverInstances refuses an AWS_-prefixed QueryParameters or OptionalParameters key with
    InvalidInput naming the key, while custom attributes filter as documented: QueryParameters match
    exactly and case-sensitively, and OptionalParameters narrow when an instance matches, else fall back."""
    sd = ctx.client("servicediscovery")
    ns_name, svc_name, svc_id = _namespace_and_service(ctx, sd)
    _register(ctx, sd, svc_id, "inst-a", {"tier": "web", "zone": "z1"})
    _register(ctx, sd, svc_id, "inst-b", {"tier": "web", "zone": "z2"})

    def ids(**kwargs) -> set:
        return set(_discover(sd, ns_name, svc_name, HealthStatus="ALL", **kwargs))

    _converge(lambda: ids(), {"inst-a", "inst-b"}, what="both registered instances discoverable")
    cases = [
        ({"QueryParameters": {"zone": "z1"}}, {"inst-a"}),
        ({"QueryParameters": {"zone": "Z1"}}, set()),
        ({"QueryParameters": {"zone": "z3"}}, set()),
        ({"QueryParameters": {"tier": "web", "zone": "z2"}}, {"inst-b"}),
        ({"OptionalParameters": {"zone": "z2"}}, {"inst-b"}),
        ({"OptionalParameters": {"zone": "z9"}}, {"inst-a", "inst-b"}),
        ({"QueryParameters": {"tier": "web"}, "OptionalParameters": {"zone": "z1"}}, {"inst-a"}),
        ({"QueryParameters": {"tier": "web"}, "OptionalParameters": {"zone": "z9"}}, {"inst-a", "inst-b"}),
        ({"QueryParameters": {"tier": "db"}, "OptionalParameters": {"zone": "z1"}}, set()),
    ]
    for kwargs, expected in cases:
        _converge(lambda kw=kwargs: ids(**kw), expected, what=f"DiscoverInstances({kwargs!r})")

    reserved = {"AWS_INSTANCE_IPV4": "192.0.2.10"}
    code, msg = _error(lambda: sd.discover_instances(
        NamespaceName=ns_name, ServiceName=svc_name, HealthStatus="ALL", QueryParameters=reserved))
    assert (code, msg) == (
        "InvalidInput",
        "Request QueryParameters contains invalid attribute: [AWS_INSTANCE_IPV4]. "
        "[aws_] prefix is reserved for AWS attributes.",
    ), f"a reserved QueryParameters key was refused with {code!r} / {msg!r}"
    code, msg = _error(lambda: sd.discover_instances(
        NamespaceName=ns_name, ServiceName=svc_name, HealthStatus="ALL", OptionalParameters=reserved))
    assert (code, msg) == (
        "InvalidInput",
        "Request OptionalParameters contains invalid attribute: [AWS_INSTANCE_IPV4]. "
        "[aws_] prefix is reserved for AWS attributes.",
    ), f"a reserved OptionalParameters key was refused with {code!r} / {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
