"""describe-identity-last-modified-is-frozen-by-reads-and-advances-on-a-new-login."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-identity-last-modified-is-frozen-by-reads-and-advances-on-a-new-login"
GROUP = "representation"
SERVICES = ["cognito-identity"]

#: N consecutive identical reads. Four, not two: a target that advanced the timestamp on every
#: SECOND read would survive a pair.
_FREEZE_READS = 4
_FREEZE_INTERVAL_S = 2.0
#: The link is an asynchronous-ish write over an identity record; the advance is polled for so a
#: coarse clock or a brief propagation window cannot flake it. Raises on timeout.
_ADVANCE_BUDGET_S = 120.0
_ADVANCE_INTERVAL_S = 3.0


def _poll_until(fn, pred, timeout_s=120.0, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) or the deadline; ClientErrors count as not-yet. Raises."""
    deadline = time.time() + timeout_s
    last = None
    last_exc = None
    while time.time() < deadline:
        try:
            last = fn()
            if pred(last):
                return last
            last_exc = None
        except ClientError as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}: last={last!r} err={last_exc!r}"
    )


def _list_all_identities(ci, pool_id, page_ceiling=20):
    """Page ListIdentities to exhaustion (bounded); never assert membership in one page."""
    out = []
    token = None
    for _ in range(page_ceiling):
        kwargs = {"IdentityPoolId": pool_id, "MaxResults": 60}
        if token:
            kwargs["NextToken"] = token
        resp = ci.list_identities(**kwargs)
        out.extend(resp["Identities"])
        token = resp.get("NextToken")
        if not token:
            return out
    raise AssertionError(
        f"ListIdentities did not terminate within {page_ceiling} pages for pool {pool_id}"
    )


# ===== check =====

@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repeated DescribeIdentity and ListIdentities reads leave an identity's CreationDate and
    LastModifiedDate unchanged; linking a developer login then advances LastModifiedDate only.
    """
    ci = ctx.client("cognito-identity")

    developer_provider = ctx.unique_name("sim2real.behav.lastmod.").replace("-", ".")[:100]
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real_behav_lastmod_").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        DeveloperProviderName=developer_provider,
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))

    identity_id = ci.get_id(IdentityPoolId=pool_id)["IdentityId"]
    ctx.on_cleanup(lambda: ci.delete_identities(IdentityIdsToDelete=[identity_id]))

    baseline = ci.describe_identity(IdentityId=identity_id)
    creation = baseline["CreationDate"]
    frozen = baseline["LastModifiedDate"]
    assert creation <= frozen, (
        f"a fresh identity cannot have been modified before it was created: CreationDate="
        f"{creation!r}, LastModifiedDate={frozen!r}"
    )
    assert not baseline.get("Logins"), (
        f"a guest identity created with no Logins must report none, got "
        f"{baseline.get('Logins')!r}"
    )

    # ---- freeze detector: reads must not advance state. ListIdentities is interleaved so a target
    # that only refreshes the timestamp on the list path is caught too.
    for attempt in range(_FREEZE_READS):
        again = ci.describe_identity(IdentityId=identity_id)
        assert again["LastModifiedDate"] == frozen, (
            f"read {attempt + 1} of {_FREEZE_READS}: DescribeIdentity is a read and must not move "
            f"LastModifiedDate; expected {frozen!r}, got {again['LastModifiedDate']!r}"
        )
        assert again["CreationDate"] == creation, (
            f"read {attempt + 1} of {_FREEZE_READS}: CreationDate must never move; expected "
            f"{creation!r}, got {again['CreationDate']!r}"
        )
        listed = [
            row for row in _list_all_identities(ci, pool_id)
            if row["IdentityId"] == identity_id
        ]
        assert len(listed) == 1, (
            f"read {attempt + 1} of {_FREEZE_READS}: ListIdentities must report the identity "
            f"exactly once, got {len(listed)} rows for {identity_id}"
        )
        assert listed[0]["LastModifiedDate"] == frozen, (
            f"read {attempt + 1} of {_FREEZE_READS}: ListIdentities and DescribeIdentity must "
            f"agree on LastModifiedDate; list says {listed[0]['LastModifiedDate']!r}, expected "
            f"{frozen!r}"
        )
        assert listed[0]["CreationDate"] == creation, (
            f"read {attempt + 1} of {_FREEZE_READS}: ListIdentities reports CreationDate "
            f"{listed[0]['CreationDate']!r}, expected {creation!r}"
        )
        # Spacing the reads is the point of a freeze detector: the target is given real wall time
        # in which it COULD wrongly advance the clock, and the next iteration asserts it did not.
        time.sleep(_FREEZE_INTERVAL_S)

    # ---- the write: link a developer login to the SAME identity. Nothing else about the identity
    # changes, so LastModifiedDate is the only clock that may move.
    developer_user_id = ctx.unique_name("sim2real-behav-devuser-")
    linked = ci.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id,
        IdentityId=identity_id,
        Logins={developer_provider: developer_user_id},
    )
    assert linked["IdentityId"] == identity_id, (
        f"the link must land on the identity it named; expected {identity_id}, got "
        f"{linked.get('IdentityId')!r}"
    )

    # ---- the terminal read is DescribeIdentity, a different operation than the mutation, and the
    # poll's terminal condition is the advance itself, so a timeout raises rather than passing.
    after = _poll_until(
        lambda: ci.describe_identity(IdentityId=identity_id),
        lambda r: r["LastModifiedDate"] > frozen,
        timeout_s=_ADVANCE_BUDGET_S,
        interval_s=_ADVANCE_INTERVAL_S,
        description=(
            f"LastModifiedDate to advance past {frozen!r} after a developer login was linked to "
            f"{identity_id}"
        ),
    )
    assert after["CreationDate"] == creation, (
        f"linking a login must not move CreationDate; expected {creation!r}, got "
        f"{after['CreationDate']!r}"
    )
    assert developer_provider in after["Logins"], (
        f"DescribeIdentity must report the linked developer provider in Logins; expected "
        f"{developer_provider!r} to be present, got {after.get('Logins')!r}"
    )
    assert after["LastModifiedDate"] >= after["CreationDate"], (
        f"LastModifiedDate {after['LastModifiedDate']!r} may not precede CreationDate "
        f"{after['CreationDate']!r}"
    )

    # ListIdentities must have moved with it: the two views cannot disagree about the same record.
    listed_after = [
        row for row in _list_all_identities(ci, pool_id)
        if row["IdentityId"] == identity_id
    ]
    assert len(listed_after) == 1, (
        f"ListIdentities must still report {identity_id} exactly once after the link, got "
        f"{len(listed_after)} rows"
    )
    assert listed_after[0]["LastModifiedDate"] == after["LastModifiedDate"], (
        f"ListIdentities reports LastModifiedDate {listed_after[0]['LastModifiedDate']!r} while "
        f"DescribeIdentity reports {after['LastModifiedDate']!r} for the same identity"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
