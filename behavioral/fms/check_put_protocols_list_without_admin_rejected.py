"""put-protocols-list-without-admin-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-protocols-list-without-admin-rejected"
GROUP = "overly-permissive"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAdminAccount fails with ResourceNotFoundException and an empty message (no admin), and PutProtocolsList
    and ListProtocolsLists then fail with AccessDeniedException
    "No default admin could be found for account <id> in Region <region>"."""
    fms = ctx.client("fms")

    # Health check: GetAdminAccount answers ResourceNotFoundException, a different code from the
    # AccessDeniedException below, so FMS is reachable with these credentials and no admin is configured.
    health_code, health_message = _client_error(lambda: fms.get_admin_account())
    assert health_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from get_admin_account (no admin configured), "
        f"got {health_code}"
    )
    # GetAdminAccount's not-found error carries an empty message.
    assert health_message == "", f"unexpected ResourceNotFoundException message: {health_message!r}"

    list_name = ctx.unique_name("sim2real-fms-protolist-")
    put_code, put_message = _client_error(
        lambda: fms.put_protocols_list(
            ProtocolsList={"ListName": list_name, "ProtocolsList": ["tcp", "udp"]}
        )
    )
    assert put_code == "AccessDeniedException", f"expected AccessDeniedException, got {put_code}"
    assert put_message == f"No default admin could be found for account {ctx.account} in Region {ctx.region}", f"unexpected AccessDeniedException message: {put_message!r}"

    # Independent terminal read at a DIFFERENT operation than the one that mutated: confirm the
    # write left no trace by asking the list op, which is gated the same way: the write did not
    # sneak a partial resource past the admin gate.
    list_code, list_message = _client_error(lambda: fms.list_protocols_lists(MaxResults=10))
    assert list_code == "AccessDeniedException", f"expected AccessDeniedException, got {list_code}"
    assert list_message == f"No default admin could be found for account {ctx.account} in Region {ctx.region}", f"unexpected AccessDeniedException message: {list_message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
