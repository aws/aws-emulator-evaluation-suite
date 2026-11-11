"""describe-contact-nonexistent-rejected."""
from __future__ import annotations

import datetime as _dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-contact-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["groundstation"]


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"expected DescribeContact to reject the nonexistent contactId, but it succeeded: {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeContact on a well-formed but nonexistent contactId raises ResourceNotFoundException,
    while the general contact-reading machinery (ListContacts) works fine for this account."""
    gs = ctx.client("groundstation")
    now = _dt.datetime.now(_dt.timezone.utc)

    # Positive control: a syntactically valid, generic ListContacts call succeeds (result may be
    # empty -- that's fine, we're proving the read path itself isn't unconditionally broken).
    listing = gs.list_contacts(
        statusList=["COMPLETED"],
        startTime=now - _dt.timedelta(days=1),
        endTime=now,
    )
    assert "contactList" in listing, f"ListContacts response missing contactList: {listing!r}"

    fake_contact_id = "00000000-0000-0000-0000-000000000000"
    refused = _error(lambda: gs.describe_contact(contactId=fake_contact_id))
    assert refused == ("ResourceNotFoundException", "Contact not found"), (
        f"expected ResourceNotFoundException for nonexistent contactId, got {refused!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
