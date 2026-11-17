"""contact-list-name-length-checked-before-existence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "contact-list-name-length-checked-before-existence"
GROUP = "contact-list"
SERVICES = ["sesv2"]

_NAME_SUFFIX_LEN = 12  # ctx.unique_name appends 12 hex characters
_TOO_LONG = ("BadRequestException",
             "ContactListName can contain up to 64 characters. Only alphanumeric characters, "
             "underscores(_) and hyphens(-) are allowed.")


def _name_of_length(ctx, tag: str, length: int) -> str:
    """A unique ContactListName candidate exactly ``length`` characters long."""
    prefix = f"sim2real-behav-clist-{tag}-"
    pad = max(0, length - _NAME_SUFFIX_LEN - len(prefix))
    name = ctx.unique_name(prefix + "x" * pad)
    assert len(name) == length, f"built name {name!r} has length {len(name)}, expected {length}"
    return name


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    err = _error(fn)
    assert err == (code, message), f"expected {(code, message)!r}, got {err!r}"


def _tolerate_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


@tags(
    "resource:account-singleton:sesv2-contact-list",
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A 65-char ContactListName is refused on Create and Get before AWS ever checks whether
    it exists; a never-created 64-char name is instead refused only for not existing."""
    ses = ctx.client("sesv2")

    prior = None
    existing = ses.list_contact_lists().get("ContactLists", [])
    if existing:
        prior_name = existing[0]["ContactListName"]
        prior = ses.get_contact_list(ContactListName=prior_name)
        ses.delete_contact_list(ContactListName=prior_name)

    def _restore():
        if prior is None:
            return
        kwargs = {"ContactListName": prior["ContactListName"]}
        for key in ("Topics", "Description", "Tags"):
            if key in prior:
                kwargs[key] = prior[key]
        ses.create_contact_list(**kwargs)

    ctx.on_cleanup(_restore)

    too_long = _name_of_length(ctx, "toolong", 65)
    expect_error(lambda: ses.create_contact_list(ContactListName=too_long), *_TOO_LONG)
    expect_error(lambda: ses.get_contact_list(ContactListName=too_long), *_TOO_LONG)

    never_created = _name_of_length(ctx, "absent", 64)
    absent_error = ("NotFoundException", f"List with name: {never_created} doesn't exist.")
    expect_error(lambda: ses.get_contact_list(ContactListName=never_created), *absent_error)

    accepted = _name_of_length(ctx, "ok", 64)
    ses.create_contact_list(ContactListName=accepted)
    ctx.on_cleanup(lambda: _tolerate_not_found(
        lambda: ses.delete_contact_list(ContactListName=accepted)))
    got = ses.get_contact_list(ContactListName=accepted)
    assert got["ContactListName"] == accepted, (
        f"expected ContactListName {accepted!r}, got {got['ContactListName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
