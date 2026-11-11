"""op-contract-delete-managed-prefix-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-managed-prefix-list"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteManagedPrefixList removes a customer-managed prefix list; deleting an
    unknown prefix list ID is rejected with InvalidPrefixListID.NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-pl-")

    created = ec2.create_managed_prefix_list(
        PrefixListName=name,
        MaxEntries=1,
        AddressFamily="IPv4",
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "Name", "Value": name}]}],
    )["PrefixList"]
    pl_id = created["PrefixListId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id)))

    def _describe():
        try:
            resp = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidPrefixListID.NotFound":
                return None
            raise
        return resp["PrefixLists"][0] if resp["PrefixLists"] else None

    created_state = _poll_until(_describe, lambda pl: pl is not None and pl["State"] == "create-complete")
    assert created_state["State"] == "create-complete", f"expected create-complete, got {created_state!r}"

    resp = ec2.delete_managed_prefix_list(PrefixListId=pl_id)
    assert resp["PrefixList"]["PrefixListId"] == pl_id, (
        f"expected DeleteManagedPrefixList to echo {pl_id}, got {resp['PrefixList']['PrefixListId']!r}"
    )

    final = _poll_until(_describe, lambda pl: pl is None or pl["State"] == "delete-complete")
    assert final is None or final["State"] == "delete-complete", f"unexpected final state: {final}"

    fake_id = "pl-00000000000000000"
    code, message = _error(lambda: ec2.delete_managed_prefix_list(PrefixListId=fake_id))
    assert code == "InvalidPrefixListID.NotFound", f"unexpected code: {code}"
    assert message == f"The prefix list ({fake_id}) does not exist.", f"unexpected message {message!r}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPrefixListID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
