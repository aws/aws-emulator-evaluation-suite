"""concurrent-analysis-template-name-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-analysis-template-name-race"
GROUP = "concurrency"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Six concurrent CreateAnalysisTemplate calls with one name in one membership yield one template and five
    ConflictExceptions; only the winner is listed, it deletes, and a second delete fails with
    ResourceNotFoundException and the exact message."""
    cr = ctx.client("cleanrooms")

    resource_tags = {"env": "sim2real", "purpose": "behavioral-check"}

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags=resource_tags,
    )["collaboration"]["id"]
    membership_ids = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, membership_ids))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED", tags=resource_tags
    )["membership"]["id"]
    membership_ids.append(membership_id)

    name = ctx.unique_name("sim2real_cr_race_").replace("-", "_")
    racer_count = 6

    def racer(i: int):
        try:
            tpl = cr.create_analysis_template(
                membershipIdentifier=membership_id,
                name=name,
                format="SQL",
                source={"text": f"SELECT {i} AS n"},
                tags=resource_tags,
            )["analysisTemplate"]
            return ("ok", tpl["id"])
        except ClientError as exc:
            return ("err", exc.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(racer, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    assert len(successes) == 1, f"expected exactly one winner, got {successes}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {failures}")
    # message varies: it names a server-generated id for each rejected template
    assert all(code == "ConflictException" for _, code in failures), failures

    winner_id = successes[0][1]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cr.delete_analysis_template(
        membershipIdentifier=membership_id, analysisTemplateIdentifier=winner_id)))

    templates = cr.list_analysis_templates(membershipIdentifier=membership_id)["analysisTemplateSummaries"]
    matching = [t for t in templates if t["name"] == name]
    assert len(matching) == 1, f"expected exactly one template named {name!r}, got {matching}"
    assert matching[0]["id"] == winner_id, (
        f"expected the race winner {winner_id!r} to be the surviving template, got {matching[0]['id']!r}")

    cr.delete_analysis_template(membershipIdentifier=membership_id, analysisTemplateIdentifier=winner_id)
    templates_after = cr.list_analysis_templates(membershipIdentifier=membership_id)["analysisTemplateSummaries"]
    assert not any(t["name"] == name for t in templates_after), (
        f"deleted winner {winner_id!r} is still visible in list_analysis_templates: {templates_after}")

    dead = _error(lambda: cr.delete_analysis_template(
        membershipIdentifier=membership_id, analysisTemplateIdentifier=winner_id))
    assert dead["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted analysis template, got {dead!r}")
    assert dead["Message"] == (
        f"No analysis template found with id {winner_id} for membership {membership_id}"
    ), dead


def _delete_collaboration_then_memberships(cr, collab_id, membership_ids):
    """The creator's ACTIVE membership cannot be deleted, so the collaboration goes first and
    each membership is deleted once it reads COLLABORATION_DELETED."""
    cr.delete_collaboration(collaborationIdentifier=collab_id)
    for membership_id in membership_ids:
        deadline = time.monotonic() + 60
        status = None
        while time.monotonic() < deadline:
            status = cr.get_membership(membershipIdentifier=membership_id)["membership"]["status"]
            if status == "COLLABORATION_DELETED":
                break
            time.sleep(2)
        else:
            raise AssertionError(f"membership {membership_id} never reached COLLABORATION_DELETED: {status}")
        cr.delete_membership(membershipIdentifier=membership_id)


def _error(fn):
    """Call fn(); return its botocore Error dict (Code, Message). An unexpected SUCCESS
    raises, so an emulator accepting what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
