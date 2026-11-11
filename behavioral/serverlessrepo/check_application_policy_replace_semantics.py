"""application-policy-replace-semantics."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-policy-replace-semantics"
GROUP = 'sharing'
SERVICES = ['serverlessrepo']

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# SAR refuses a statement whose principal is the application's own owner ("You cannot set principal
# to resource owner"), so a grantee has to be an account other than the one running the check.
# Nothing is ever created in them, and the grant lives only until the application is deleted.
_GRANTEE_CANDIDATES = ("123456789012", "111111111111", "000000000000")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


# SAR's read path is eventually consistent (GetApplication can serve a just-published version only
# seconds later), so every read-back below is polled to the state the write claimed. A poll that
# never converges fails with the divergence, which is the assertion; asserting on the first
# response would make each one a race.
_CONSISTENCY_BUDGET_S = 120.0


def _await_policy(sar, app_id, expected, what):
    """Poll GetApplicationPolicy until its statements equal expected, keyed by StatementId."""
    deadline = time.time() + _CONSISTENCY_BUDGET_S
    seen = None
    want = sorted(expected, key=lambda s: s["StatementId"])
    while time.time() < deadline:
        try:
            seen = sar.get_application_policy(ApplicationId=app_id)["Statements"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
            seen = "NotFoundException"  # the application itself is not readable yet
        else:
            if sorted(seen, key=lambda s: s["StatementId"]) == want:
                return seen
        time.sleep(2)
    raise AssertionError(
        f"{what}: the application policy settled on {seen!r}, expected {want!r}"
    )


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """PutApplicationPolicy replaces the whole statement list: a statement without a StatementId comes
    back with a SAR-minted UUID that survives a read, a second Put erases the statements it omits, and
    an empty list revokes every grant."""
    sar = ctx.client("serverlessrepo")
    owner = ctx.client("sts").get_caller_identity()["Account"]
    grantees = [g for g in _GRANTEE_CANDIDATES if g != owner]
    assert len(grantees) >= 2, (
        f"the account under test {owner!r} collides with the placeholder grantees "
        f"{_GRANTEE_CANDIDATES!r}; this check needs two ids that are not the application owner"
    )
    first_grantee, second_grantee = grantees[0], grantees[1]

    name = ctx.unique_name("sim2real-behav-sar-")
    app_id = sar.create_application(
        Name=name, Author="sim2real behav", Description="policy replace semantics",
    )["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))

    _await_policy(sar, app_id, [], "an application that was never shared has no policy statements")

    # A statement with no StatementId: SAR mints one, and the minted value must survive a read.
    put = sar.put_application_policy(
        ApplicationId=app_id,
        Statements=[{"Actions": ["Deploy"], "Principals": [first_grantee]}],
    )
    assert len(put["Statements"]) == 1, (
        f"putting one statement returned {len(put['Statements'])} statements: "
        f"{put['Statements']!r}"
    )
    minted_id = put["Statements"][0]["StatementId"]
    assert _UUID_RE.match(minted_id), (
        f"SAR returned StatementId {minted_id!r} for a statement that omitted one; expected a "
        f"server-minted lowercase UUID"
    )
    assert put["Statements"][0]["PrincipalOrgIDs"] == [], (
        f"PutApplicationPolicy echoed PrincipalOrgIDs "
        f"{put['Statements'][0]['PrincipalOrgIDs']!r} for an account-principal statement, "
        f"expected an empty list"
    )

    # Get must converge on exactly what Put reported, minted StatementId included.
    _await_policy(sar, app_id, put["Statements"],
                  "after putting one statement with no StatementId")

    # Two explicitly-identified statements, so the replace below has something to erase.
    sar.put_application_policy(
        ApplicationId=app_id,
        Statements=[
            {"StatementId": "sim2real-behav-read", "Actions": ["GetApplication"],
             "Principals": [first_grantee]},
            {"StatementId": "sim2real-behav-deploy", "Actions": ["Deploy"],
             "Principals": [second_grantee]},
        ],
    )
    both = _await_policy(sar, app_id, [
        {"StatementId": "sim2real-behav-read", "Actions": ["GetApplication"],
         "Principals": [first_grantee], "PrincipalOrgIDs": []},
        {"StatementId": "sim2real-behav-deploy", "Actions": ["Deploy"],
         "Principals": [second_grantee], "PrincipalOrgIDs": []},
    ], "after putting two named statements")
    assert minted_id not in {s["StatementId"] for s in both}, (
        f"the earlier server-minted statement {minted_id!r} survived a Put that did not include "
        f"it — PutApplicationPolicy replaces the statement list, it does not merge into it"
    )

    # The replace: one statement in, so the other must be gone.
    sar.put_application_policy(
        ApplicationId=app_id,
        Statements=[{"StatementId": "sim2real-behav-deploy", "Actions": ["Deploy"],
                     "Principals": [second_grantee]}],
    )
    _await_policy(sar, app_id, [
        {"StatementId": "sim2real-behav-deploy", "Actions": ["Deploy"],
         "Principals": [second_grantee], "PrincipalOrgIDs": []},
    ], "after replacing the policy with a single statement, sim2real-behav-read must be erased")

    # An empty statement list is the revocation, not a no-op that leaves the grant standing.
    sar.put_application_policy(ApplicationId=app_id, Statements=[])
    _await_policy(sar, app_id, [], "after putting an empty statement list")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
