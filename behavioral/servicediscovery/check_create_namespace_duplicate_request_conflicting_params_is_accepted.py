"""create-namespace-duplicate-request-conflicting-params-is-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-namespace-duplicate-request-conflicting-params-is-accepted"
GROUP = "error-semantics"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a completed CreatePrivateDnsNamespace's CreatorRequestId with a different Name creates a
    new namespace with a distinct OperationId and NamespaceId; both namespaces read back under their
    own names and each name lists only its own id."""
    sd = ctx.client("servicediscovery")
    vpc_id = _create_vpc(ctx)
    creator_request_id = ctx.unique_name("sim2real-crid-")
    name1 = f"{ctx.unique_name('sim2real-privns-a-')}.com"
    name2 = f"{ctx.unique_name('sim2real-privns-b-')}.com"

    first = sd.create_private_dns_namespace(
        Name=name1,
        Vpc=vpc_id,
        CreatorRequestId=creator_request_id,
        Tags=[{"Key": "sim2real-behav", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _cleanup_namespace(sd, first["OperationId"]))

    # Ensure the original create has fully completed before probing the
    # mismatched-params retry, so the response reflects steady state rather
    # than an operation still in progress.
    op1 = _poll_operation(sd, first["OperationId"], timeout_s=180.0)
    assert op1["Status"] == "SUCCESS", f"create failed: {op1.get('ErrorMessage')}"
    ns1_id = op1["Targets"]["NAMESPACE"]

    second = sd.create_private_dns_namespace(
        Name=name2,
        Vpc=vpc_id,
        CreatorRequestId=creator_request_id,
        Tags=[{"Key": "sim2real-behav", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _cleanup_namespace(sd, second["OperationId"]))

    # It is NOT rejected, and it is NOT the same operation as the first call.
    assert second["OperationId"] != first["OperationId"], (
        "a mismatched-params retry must not be folded into the original operation"
    )

    op2 = _poll_operation(sd, second["OperationId"], timeout_s=180.0)
    assert op2["Status"] == "SUCCESS", f"second create failed: {op2.get('ErrorMessage')}"
    ns2_id = op2["Targets"]["NAMESPACE"]
    assert ns2_id != ns1_id, "the retry must create a genuinely distinct namespace"

    # Both namespaces coexist independently under their own names/IDs.
    ns1 = sd.get_namespace(Id=ns1_id)["Namespace"]
    ns2 = sd.get_namespace(Id=ns2_id)["Namespace"]
    assert ns1["Name"] == name1, f"expected namespace {ns1_id} to be named {name1!r}, got {ns1['Name']!r}"
    assert ns2["Name"] == name2, f"expected namespace {ns2_id} to be named {name2!r}, got {ns2['Name']!r}"
    assert ns1["Id"] != ns2["Id"], f"the two independently-read namespaces must not alias, both read as {ns1['Id']!r}"

    matches1 = sd.list_namespaces(
        Filters=[{"Name": "NAME", "Values": [name1], "Condition": "EQ"}]
    )["Namespaces"]
    matches2 = sd.list_namespaces(
        Filters=[{"Name": "NAME", "Values": [name2], "Condition": "EQ"}]
    )["Namespaces"]
    assert [m["Id"] for m in matches1] == [ns1_id], (
        f"expected ListNamespaces(name={name1!r}) to return exactly [{ns1_id!r}], got {[m['Id'] for m in matches1]!r}"
    )
    assert [m["Id"] for m in matches2] == [ns2_id], (
        f"expected ListNamespaces(name={name2!r}) to return exactly [{ns2_id!r}], got {[m['Id'] for m in matches2]!r}"
    )


def _create_vpc(ctx):
    """The run's shared network VPC, which the private DNS namespace is associated with."""
    return ctx.network().vpc_id


def _error_response(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]


def _poll_operation(sd, operation_id, timeout_s=180.0, interval_s=3.0):
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


def _cleanup_namespace(sd, op_id):
    deadline = time.monotonic() + 120.0
    ns_id = None
    while time.monotonic() < deadline:
        try:
            op = sd.get_operation(OperationId=op_id)["Operation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "OperationNotFound":
                raise
            return
        if op["Status"] in ("SUCCESS", "FAIL"):
            ns_id = op.get("Targets", {}).get("NAMESPACE")
            break
        time.sleep(3.0)
    if ns_id:
        try:
            sd.delete_namespace(Id=ns_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NamespaceNotFound":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
