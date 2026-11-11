"""credential-locker-quota-exceeded-accepted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "credential-locker-quota-exceeded-accepted"
GROUP = "crud-depth"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CredentialLocker has no per-account count quota (Service Quotas lists only rate limits).

    A second CreateCredentialLocker succeeds alongside the first; both are gettable and listed,
    and deleting one does not disturb the other."""
    iot = _iot_client(ctx)

    first = iot.create_credential_locker(Tags={"env": "sim2real", "purpose": "test"})
    first_id = first["Id"]
    ctx.on_cleanup(lambda: _delete_locker_ignore_missing(iot, first_id))

    second = iot.create_credential_locker(Tags={"env": "sim2real", "purpose": "test"})
    second_id = second["Id"]
    ctx.on_cleanup(lambda: _delete_locker_ignore_missing(iot, second_id))
    assert second_id and second_id != first_id, (
        f"expected a second, distinct locker id; got {second_id!r} vs first {first_id!r}"
    )

    listed = _locker_ids(iot)
    assert {first_id, second_id} <= listed, f"expected both lockers listed, got {listed!r}"

    got_first = iot.get_credential_locker(Identifier=first_id)
    assert got_first["Id"] == first_id, f"expected Id {first_id!r}, got {got_first.get('Id')!r}"
    got_second = iot.get_credential_locker(Identifier=second_id)
    assert got_second["Id"] == second_id, (
        f"expected Id {second_id!r}, got {got_second.get('Id')!r}"
    )

    iot.delete_credential_locker(Identifier=first_id)
    not_found_first, not_found_first_msg = _error(lambda: iot.get_credential_locker(Identifier=first_id))
    assert not_found_first == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {not_found_first!r}"
    )
    assert not_found_first_msg == 'resource does not exist', not_found_first_msg
    remaining = _locker_ids(iot)
    assert second_id in remaining and first_id not in remaining, (
        f"deleting the first locker must not disturb the second; expected {second_id!r} "
        f"listed and {first_id!r} gone, got {remaining!r}"
    )

    iot.delete_credential_locker(Identifier=second_id)
    not_found_second, not_found_second_msg = _error(lambda: iot.get_credential_locker(Identifier=second_id))
    assert not_found_second == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {not_found_second!r}"
    )
    assert not_found_second_msg == 'resource does not exist', not_found_second_msg


def _locker_ids(iot) -> set[str]:
    """Every credential locker id in the account, read across all pages."""
    return {
        item["Id"]
        for page in iot.get_paginator("list_credential_lockers").paginate()
        for item in page.get("Items", [])
    }


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the runner's
    # default region (us-west-2) has no endpoint for it, so pin the region on real AWS. This
    # goes through ctx.client (not a hand-rolled boto3.client) so the check's own
    # credentials are used rather than the ambient chain.
    return ctx.client("iot-managed-integrations", region="eu-west-1")
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_locker_ignore_missing(iot, locker_id: str) -> None:
    try:
        iot.delete_credential_locker(Identifier=locker_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
