"""member-lookup-requires-exact-post-normalization-casing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "member-lookup-requires-exact-post-normalization-casing"
GROUP = 'address-list-members'
SERVICES = ['mailmanager']


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A lookup matches only the exact, post-normalization address string: a case
    variant of a registered address is reported as not found, never matched.
    """
    mm = ctx.client("mailmanager")
    al_id = mm.create_address_list(
        AddressListName=ctx.unique_name("sim2real-behav-mm-al-")
    )["AddressListId"]
    ctx.on_cleanup(lambda: mm.delete_address_list(AddressListId=al_id))

    local_part = ctx.unique_name("CaseProbe-")
    stored = f"{local_part}@example.com"
    mm.register_member_to_address_list(AddressListId=al_id, Address=stored)

    # Positive control: the exact, already-normalized form matches.
    got = mm.get_member_of_address_list(AddressListId=al_id, Address=stored)
    assert got["Address"] == stored, f"get returned {got['Address']!r}, expected {stored!r}"

    expected_message = f"Could not find Address in AddressList {al_id} of AWS account {ctx.account}"
    for variant in (stored.lower(), stored.upper()):
        if variant == stored:
            continue
        code, message = _error(
            lambda v=variant: mm.get_member_of_address_list(AddressListId=al_id, Address=v)
        )
        assert code == "ResourceNotFoundException", (
            f"looking up {variant!r} (a case variant of the registered {stored!r}) "
            f"gave {code!r}, expected ResourceNotFoundException"
        )
        assert message == expected_message, f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
