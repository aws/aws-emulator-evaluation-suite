"""update-private-dns-namespace-properties."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-private-dns-namespace-properties"
GROUP = "state-machine"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrivateDnsNamespace changes the Description in place, keeping the namespace's Id and Arn;
    after DeleteNamespace, GetNamespace answers NamespaceNotFound with an empty message and a further
    update answers NamespaceNotFound naming the id."""
    sd = ctx.client("servicediscovery")
    vpc_id = _create_vpc(ctx)
    name = f"{ctx.unique_name('sim2real-privns-')}.com"

    create_op_id = sd.create_private_dns_namespace(
        Name=name, Vpc=vpc_id, Description="original description"
    )["OperationId"]
    op = _poll_operation(ctx, sd, create_op_id, timeout_s=240.0)
    assert op["Status"] == "SUCCESS", f"create failed: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(sd, ns_id))

    before = sd.get_namespace(Id=ns_id)["Namespace"]
    assert before["Description"] == "original description", (
        f"expected freshly-created Description 'original description', got {before['Description']!r}"
    )

    update_op_id = sd.update_private_dns_namespace(
        Id=ns_id, Namespace={"Description": "updated description"}
    )["OperationId"]
    update_op = _poll_operation(ctx, sd, update_op_id, timeout_s=180.0)
    assert update_op["Status"] == "SUCCESS", f"update failed: {update_op.get('ErrorMessage')}"

    after = sd.get_namespace(Id=ns_id)["Namespace"]
    assert after["Id"] == before["Id"], f"Id must not change on update: before={before['Id']!r} after={after['Id']!r}"
    assert after["Arn"] == before["Arn"], (
        f"Arn must not change on update: before={before['Arn']!r} after={after['Arn']!r}"
    )
    assert after["Description"] == "updated description", (
        f"expected updated Description to persist, got {after['Description']!r}"
    )

    delete_op_id = sd.delete_namespace(Id=ns_id)["OperationId"]
    delete_op = _poll_operation(ctx, sd, delete_op_id, timeout_s=180.0)
    assert delete_op["Status"] == "SUCCESS", f"delete failed: {delete_op.get('ErrorMessage')}"

    gone = _poll_until_not_found(sd, ns_id, timeout_s=60.0)
    assert gone.get("Code") == "NamespaceNotFound", f"expected NamespaceNotFound after delete, got {gone!r}"
    assert gone.get("Message") == "", f"expected an empty NamespaceNotFound message, got {gone.get('Message')!r}"

    mutate = _client_error(
        lambda: sd.update_private_dns_namespace(Id=ns_id, Namespace={"Description": "should-not-apply"})
    )
    assert mutate.get("Code") == "NamespaceNotFound", (
        f"expected update on a deleted namespace to fail NamespaceNotFound, got {mutate!r}"
    )
    assert mutate.get("Message") == ns_id, (
        f"expected NamespaceNotFound message {ns_id!r}, got {mutate.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
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


def _poll_until_not_found(sd, ns_id, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = sd.get_namespace(Id=ns_id)["Namespace"]
        except ClientError as e:
            last = e.response["Error"]
            if last.get("Code") == "NamespaceNotFound":
                return last
        time.sleep(interval_s)
    raise AssertionError(
        f"namespace {ns_id} was not reported NamespaceNotFound within {timeout_s}s after delete "
        f"(last observed={last!r})"
    )


def _create_vpc(ctx):
    ec2 = ctx.client("ec2")
    resp = ec2.create_vpc(
        CidrBlock="10.43.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _safe_delete_namespace(sd, ns_id):
    if not ns_id:
        return
    try:
        sd.delete_namespace(Id=ns_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NamespaceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
