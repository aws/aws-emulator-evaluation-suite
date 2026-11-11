"""concurrent-contact-creation-exactly-one-succeeds."""
from __future__ import annotations

import concurrent.futures

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-contact-creation-exactly-one-succeeds"
GROUP = 'concurrency'
SERVICES = ['sesv2']

@tags("resource:account-singleton:sesv2-contact-list", "axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of 6 concurrent CreateContact calls for one address exactly one succeeds, every loser fails with
    AlreadyExistsException and its exact message or ConcurrentModificationException, and one contact is listed.
    """
    ses = ctx.client("sesv2")
    list_name = ctx.unique_name("sim2real-behav-clist-race-")
    # SES allows only one contact list per account; delete leftover sim2real lists first.
    try:
        for _e in ses.list_contact_lists().get("ContactLists", []):
            if not _e["ContactListName"].startswith("sim2real-"):
                continue  # not a sim2real list: leave it
            try:
                ses.delete_contact_list(ContactListName=_e["ContactListName"])
            except Exception:
                pass
    except Exception:
        pass
    ses.create_contact_list(ContactListName=list_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda _k=list_name: ses.delete_contact_list(ContactListName=_k))

    email = ctx.unique_name("sim2real-behav-contact-race-") + "@example.com"
    n = 6

    def create_attempt():
        return ses.create_contact(ContactListName=list_name, EmailAddress=email)

    # Fire N racers at once; capture each outcome (result or the exception it
    # raised) so the distribution of outcomes can be asserted.
    results = [None] * n
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        futs = {ex.submit(create_attempt): i for i in range(n)}
        for fut in concurrent.futures.as_completed(futs):
            i = futs[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for assertion
                results[i] = exc
    ctx.on_cleanup(lambda: ses.delete_contact(ContactListName=list_name, EmailAddress=email))

    n_success = sum(1 for r in results if not isinstance(r, BaseException))
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append((r.response.get("Error", {}).get("Code"), r.response.get("Error", {}).get("Message")))
        elif isinstance(r, BaseException):
            codes.append((type(r).__name__, str(r)))

    assert n_success == 1, f"expected exactly one success under contention, got {n_success}: {results}"
    assert n_success + len(codes) == n, (
        f"expected {n} outcomes, got {n_success} successes + {len(codes)} failures"
    )
    # every loser must lose for the RIGHT reason — a uniqueness conflict, not a
    # generic 5xx or throttle.
    already_exists = ("AlreadyExistsException", f"{email} already exists in List.")
    assert all(
        error == already_exists or error[0] == "ConcurrentModificationException"
        for error in codes
    ), f"unexpected failures under contention: {codes}"

    # the durable contract: contention produces exactly ONE contact, never dupes
    got = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    assert got["EmailAddress"] == email, got["EmailAddress"]
    listed = ses.list_contacts(ContactListName=list_name)
    matching = [c for c in listed.get("Contacts", []) if c["EmailAddress"] == email]
    assert len(matching) == 1, f"expected exactly 1 contact after race, got {len(matching)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
