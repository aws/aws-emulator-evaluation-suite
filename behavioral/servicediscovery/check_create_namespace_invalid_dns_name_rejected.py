"""create-namespace-invalid-dns-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-namespace-invalid-dns-name-rejected"
GROUP = "negative-classes"
SERVICES = ["servicediscovery"]

_FAKE_VPC_ID = "vpc-0123456789abcdef0"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePrivateDnsNamespace with a space in the Name is refused with InvalidInput and its exact
    message and persists nothing, while the same call with a valid name is accepted and its operation
    reaches FAIL on the nonexistent VPC: the refusal is about the name."""
    sd = ctx.client("servicediscovery")
    bad_name = "not a valid dns name!!"

    code, message = _error(
        lambda: sd.create_private_dns_namespace(Name=bad_name, Vpc=_FAKE_VPC_ID)
    )
    assert code == "InvalidInput", f"expected InvalidInput for name {bad_name!r}, got {code!r}"
    assert message == (
        f"1 validation error detected: Value '{bad_name}' at 'name' "
        f"failed to satisfy constraint: Member must satisfy regular expression pattern: ^(?!arn:)[!-~]{{1,253}}$"
    ), f"unexpected InvalidInput message: {message!r}"

    # Effect absent: no namespace/operation was ever created for the rejected name.
    matches = sd.list_namespaces(
        Filters=[{"Name": "NAME", "Values": [bad_name], "Condition": "EQ"}]
    )["Namespaces"]
    assert matches == [], f"rejected name {bad_name!r} must not have been persisted, found {matches!r}"

    # Positive control: same call shape, syntactically valid name, is accepted
    # (returns an OperationId synchronously) even though the fake VPC will make the
    # async hosted-zone-association step fail later, read below through an
    # independent GetOperation.
    good_name = f"{ctx.unique_name('sim2real-privns-')}.com"
    resp = sd.create_private_dns_namespace(
        Name=good_name,
        Vpc=_FAKE_VPC_ID,
        Tags=[{"Key": "sim2real-audit", "Value": "true"}],
    )
    op_id = resp["OperationId"]
    assert op_id, "CreatePrivateDnsNamespace with a valid name returned no OperationId"
    ctx.on_cleanup(lambda: _cleanup_namespace(ctx, sd, op_id))

    op = _wait_terminal(sd, op_id)
    assert op["Status"] == "FAIL", (
        f"expected the async step to fail against the nonexistent VPC {_FAKE_VPC_ID!r}, "
        f"got Status={op['Status']!r}, ErrorMessage={op.get('ErrorMessage')!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_terminal(sd, op_id, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=op_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(
        f"operation {op_id} did not reach a terminal state within {timeout_s}s "
        f"(last status={op['Status'] if op else None!r})"
    )


def _cleanup_namespace(ctx, sd, op_id):
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
