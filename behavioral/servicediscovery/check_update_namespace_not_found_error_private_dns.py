"""update-namespace-not-found-error-private-dns."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-namespace-not-found-error-private-dns"
GROUP = "error-semantics"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrivateDnsNamespace on a deleted namespace ID is rejected with NamespaceNotFound and
    leaves it absent, while the same call on an existing namespace succeeds and persists."""
    sd = ctx.client("servicediscovery")
    vpc_id, vpc_created = _get_or_create_vpc(ctx)
    if vpc_created:
        ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))
    tag_value = ctx.unique_name("sim2real-upd404")

    # Namespace that will be deleted before we try to update it.
    gone_name = f"{ctx.unique_name('sim2real-upd404-ns')}.example.com"
    resp = sd.create_private_dns_namespace(
        Name=gone_name, Vpc=vpc_id, Tags=[{"Key": "sim2real-check", "Value": tag_value}]
    )
    op = _wait_operation(ctx, resp["OperationId"])
    assert op["Status"] == "SUCCESS", f"create ended in {op['Status']}: {op.get('ErrorMessage')}"
    gone_id = op["Targets"]["NAMESPACE"]

    delete_resp = sd.delete_namespace(Id=gone_id)
    del_op = _wait_operation(ctx, delete_resp["OperationId"])
    assert del_op["Status"] == "SUCCESS", f"delete ended in {del_op['Status']}: {del_op.get('ErrorMessage')}"
    deadline = _deadline(ctx, 120.0)
    while time.monotonic() < deadline:
        if _namespace_or_error(sd, gone_id).get("Code") == "NamespaceNotFound":
            break
        time.sleep(2)
    else:
        raise AssertionError("namespace never reported deleted before the update attempt")

    error = _client_error(
        lambda: sd.update_private_dns_namespace(Id=gone_id, Namespace={"Description": "should-not-apply"})
    )
    assert error.get("Code") == "NamespaceNotFound", (
        f"expected NamespaceNotFound updating a deleted namespace, got {error!r}"
    )
    assert error.get("Message") == gone_id, (
        f"expected NamespaceNotFound message {gone_id!r}, got {error.get('Message')!r}"
    )

    # No partial mutation / resurrection: still gone.
    error2 = _client_error(lambda: sd.get_namespace(Id=gone_id))
    assert error2.get("Code") == "NamespaceNotFound", f"expected the deleted namespace to stay gone, got {error2!r}"
    assert error2.get("Message") == "", f"expected an empty NamespaceNotFound message, got {error2.get('Message')!r}"

    # Positive control: updating a real, still-existing namespace succeeds and persists.
    ok_name = f"{ctx.unique_name('sim2real-upd-ok-ns')}.example.com"
    resp2 = sd.create_private_dns_namespace(
        Name=ok_name, Vpc=vpc_id, Tags=[{"Key": "sim2real-check", "Value": tag_value}]
    )
    op2 = _wait_operation(ctx, resp2["OperationId"])
    assert op2["Status"] == "SUCCESS", f"second create ended in {op2['Status']}: {op2.get('ErrorMessage')}"
    ok_id = op2["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(ctx, ok_id))

    update_resp = sd.update_private_dns_namespace(Id=ok_id, Namespace={"Description": "updated-by-check"})
    upd_op = _wait_operation(ctx, update_resp["OperationId"])
    assert upd_op["Status"] == "SUCCESS", f"update ended in {upd_op['Status']}: {upd_op.get('ErrorMessage')}"
    got2 = sd.get_namespace(Id=ok_id)["Namespace"]
    assert got2["Description"] == "updated-by-check", (
        f"expected Description 'updated-by-check' on the still-existing namespace, got {got2['Description']!r}"
    )


# ===== helpers =====
def _deadline(ctx, cap_s: float) -> float:
    """A monotonic deadline `cap_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (cap_s if left is None else min(cap_s, max(left - 5.0, 1.0)))


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _namespace_or_error(sd, namespace_id):
    """GetNamespace's Namespace on success, its Error dict on a ClientError."""
    try:
        return sd.get_namespace(Id=namespace_id)["Namespace"]
    except ClientError as e:
        return e.response["Error"]


def _wait_operation(ctx, operation_id, timeout_s: float = 240.0, interval_s: float = 3.0):
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        if time.monotonic() > deadline:
            raise AssertionError(
                f"operation {operation_id} did not reach a terminal state within {timeout_s}s "
                f"(last status={op['Status']})"
            )
        time.sleep(interval_s)


def _get_or_create_vpc(ctx) -> tuple[str, bool]:
    """Adopt an existing VPC (default preferred) if one is available; otherwise create a
    minimal one, so the check does not depend on an ambient shared network that a freshly
    provisioned account may not have. Returns (vpc_id, created_by_this_check)."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    return vpcs[0]["VpcId"], False


def _safe_delete_vpc(ctx, vpc_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise
        return


def _safe_delete_namespace(ctx, namespace_id: str) -> None:
    sd = ctx.client("servicediscovery")
    try:
        resp = sd.delete_namespace(Id=namespace_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NamespaceNotFound":
            raise
        return
    op_id = resp.get("OperationId")
    if not op_id:
        return
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            op = sd.get_operation(OperationId=op_id)["Operation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "OperationNotFound":
                raise
            return
        if op["Status"] in ("SUCCESS", "FAIL"):
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
