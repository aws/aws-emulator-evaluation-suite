"""lens-upgrade-preserves-recorded-answers."""
from __future__ import annotations

import json
import time
import uuid
from collections import Counter

from behavioral_harness import tags

CHECK = "lens-upgrade-preserves-recorded-answers"
GROUP = 'custom-lens'
SERVICES = ['wellarchitected']

_RISKS = ("UNANSWERED", "HIGH", "MEDIUM", "NONE", "NOT_APPLICABLE")


def _poll(fn, want, what, timeout=180.0, interval=2.0):
    """Poll fn() until want(value) holds. Both the NOT_CURRENT transition that publishing a new
    lens version causes and the RiskCounts aggregate are derived asynchronously."""
    deadline = time.time() + timeout
    while True:
        value = fn()
        if want(value):
            return value
        if time.time() >= deadline:
            raise AssertionError(f"{what}: never held within {timeout}s; last observed {value!r}")
        time.sleep(interval)


def _all_answers(wa, **kw):
    """ListAnswers has no botocore paginator; loop the NextToken."""
    out, token = [], None
    while True:
        page = wa.list_answers(NextToken=token, **kw) if token else wa.list_answers(**kw)
        out.extend(page["AnswerSummaries"])
        token = page.get("NextToken")
        if not token:
            return out


def _histogram(answers):
    counts = Counter(a["Risk"] for a in answers)
    return {r: counts.get(r, 0) for r in _RISKS}


def _lens_json(name, question_ids):
    """A custom lens with authored riskRules: both choices -> NO_RISK, the first alone ->
    MEDIUM_RISK, anything else -> HIGH_RISK. Ids must be 3-128 chars of [A-Za-z0-9_]."""
    questions = []
    for qid in question_ids:
        questions.append({
            "id": qid,
            "title": f"Question {qid}",
            "description": "sim2real behavioral check question",
            "choices": [
                {"id": f"{qid}_c1", "title": "First choice",
                 "helpfulResource": {"displayText": "resource"},
                 "improvementPlan": {"displayText": "plan"}},
                {"id": f"{qid}_c2", "title": "Second choice",
                 "helpfulResource": {"displayText": "resource"},
                 "improvementPlan": {"displayText": "plan"}},
            ],
            "riskRules": [
                {"condition": f"{qid}_c1 && {qid}_c2", "risk": "NO_RISK"},
                {"condition": f"{qid}_c1", "risk": "MEDIUM_RISK"},
                {"condition": "default", "risk": "HIGH_RISK"},
            ],
        })
    return json.dumps({
        "schemaVersion": "2021-11-01",
        "name": name,
        "description": "sim2real behavioral check lens",
        "pillars": [{"id": "sim2realpillar", "name": "Sim2Real Pillar", "questions": questions}],
    })


def _create_workload(ctx, wa, name, lenses):
    """CreateWorkload + its teardown. AwsRegions is required by the service though the Smithy
    model marks neither AwsRegions nor NonAwsRegions required."""
    wid = wa.create_workload(
        WorkloadName=name,
        Description="sim2real behavioral check workload",
        Environment="PREPRODUCTION",
        ReviewOwner="sim2real@example.com",
        Lenses=lenses,
        AwsRegions=[ctx.region],
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=wid, ClientRequestToken=str(uuid.uuid4()))
    )
    return wid


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Publishing lens version 2.0 marks the review NOT_CURRENT, and UpgradeLensReview carries every
    recorded answer and its Risk to 2.0, adds the new question as UNANSWERED, and records a milestone
    holding the 1.0 counts.
    """
    wa = ctx.client("wellarchitected")
    lens_name = ctx.unique_name("sim2real-behav-lens-")
    v1_questions = ["sqkeep", "sqmove"]
    v2_questions = v1_questions + ["sqadded"]

    lens_arn = wa.import_lens(
        JSONString=_lens_json(lens_name, v1_questions),
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["LensArn"]
    ctx.on_cleanup(
        lambda: wa.delete_lens(
            LensAlias=lens_arn, LensStatus="ALL", ClientRequestToken=str(uuid.uuid4()),
        )
    )
    wa.create_lens_version(
        LensAlias=lens_arn, LensVersion="1.0", IsMajorVersion=True,
        ClientRequestToken=str(uuid.uuid4()),
    )
    wid = _create_workload(
        ctx, wa, ctx.unique_name("sim2real-behav-wa-upg-"), ["wellarchitected", lens_arn],
    )

    kept = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqkeep",
        SelectedChoices=["sqkeep_c1", "sqkeep_c2"], Notes="recorded against lens version 1.0",
    )["Answer"]
    assert kept["Risk"] == "NONE", f"expected NONE for a fully answered question, got {kept['Risk']!r}"
    moved = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqmove", SelectedChoices=["sqmove_c1"],
    )["Answer"]
    assert moved["Risk"] == "MEDIUM", f"expected MEDIUM for the first choice alone, got {moved['Risk']!r}"

    before = _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens_arn)["LensReview"],
        lambda lr: lr["RiskCounts"]["UNANSWERED"] == 0,
        "the version 1.0 review never became fully answered",
    )
    assert before["LensStatus"] == "CURRENT", (
        f"a review of the newest lens version reads LensStatus {before['LensStatus']!r}, "
        f"expected CURRENT"
    )
    counts_v1 = before["RiskCounts"]

    # Publish 2.0 with one extra question.
    wa.import_lens(
        LensAlias=lens_arn, JSONString=_lens_json(lens_name, v2_questions),
        ClientRequestToken=str(uuid.uuid4()),
    )
    wa.create_lens_version(
        LensAlias=lens_arn, LensVersion="2.0", IsMajorVersion=True,
        ClientRequestToken=str(uuid.uuid4()),
    )

    stale = _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens_arn)["LensReview"],
        lambda lr: lr["LensStatus"] == "NOT_CURRENT",
        "publishing lens version 2.0 never marked the existing review NOT_CURRENT",
    )
    assert stale["LensVersion"] == "1.0", (
        f"the un-upgraded review moved to lens version {stale['LensVersion']!r} on its own; "
        f"it must stay pinned to '1.0' until UpgradeLensReview is called"
    )
    assert stale["RiskCounts"] == counts_v1, (
        f"publishing a new lens version changed the un-upgraded review's counts to "
        f"{stale['RiskCounts']!r}, expected the unchanged {counts_v1!r}"
    )
    assert len(_all_answers(wa, WorkloadId=wid, LensAlias=lens_arn)) == len(v1_questions), (
        "the un-upgraded review already shows the question that 2.0 added"
    )

    diff = wa.get_lens_version_difference(LensAlias=lens_arn, BaseLensVersion="1.0")
    assert diff["TargetLensVersion"] == "2.0", (
        f"the version difference targets {diff['TargetLensVersion']!r}, expected '2.0'"
    )
    assert diff["LatestLensVersion"] == "2.0", (
        f"the latest lens version reads {diff['LatestLensVersion']!r}, expected '2.0'"
    )
    added = {
        (q["QuestionId"], q["DifferenceStatus"])
        for p in diff["VersionDifferences"]["PillarDifferences"]
        for q in p.get("QuestionDifferences", [])
    }
    assert ("sqadded", "NEW") in added, (
        f"the 1.0 -> 2.0 difference does not report 'sqadded' as NEW; it reports {sorted(added)!r}"
    )

    upgrade_milestone = ctx.unique_name("sim2real-behav-upg-ms-")
    wa.upgrade_lens_review(
        WorkloadId=wid, LensAlias=lens_arn, MilestoneName=upgrade_milestone,
        ClientRequestToken=str(uuid.uuid4()),
    )
    after = _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens_arn)["LensReview"],
        lambda lr: lr["LensStatus"] == "CURRENT",
        "the review never returned to CURRENT after UpgradeLensReview",
    )
    assert after["LensVersion"] == "2.0", (
        f"the upgraded review is pinned to lens version {after['LensVersion']!r}, expected '2.0'"
    )

    migrated = {a["QuestionId"]: a for a in _all_answers(wa, WorkloadId=wid, LensAlias=lens_arn)}
    assert sorted(migrated) == sorted(v2_questions), (
        f"the upgraded review holds questions {sorted(migrated)!r}, expected {sorted(v2_questions)!r}"
    )
    assert migrated["sqkeep"]["SelectedChoices"] == ["sqkeep_c1", "sqkeep_c2"], (
        f"the upgrade lost the recorded selection: sqkeep reads "
        f"{migrated['sqkeep']['SelectedChoices']!r}"
    )
    assert migrated["sqkeep"]["Risk"] == "NONE", (
        f"sqkeep's derived risk became {migrated['sqkeep']['Risk']!r} across the upgrade, expected NONE"
    )
    assert migrated["sqmove"]["SelectedChoices"] == ["sqmove_c1"], (
        f"the upgrade lost sqmove's selection: {migrated['sqmove']['SelectedChoices']!r}"
    )
    assert migrated["sqmove"]["Risk"] == "MEDIUM", (
        f"sqmove's derived risk became {migrated['sqmove']['Risk']!r} across the upgrade, expected MEDIUM"
    )
    assert migrated["sqadded"]["Risk"] == "UNANSWERED", (
        f"the question introduced by 2.0 arrived as {migrated['sqadded']['Risk']!r}, expected UNANSWERED"
    )
    assert wa.get_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqkeep",
    )["Answer"]["Notes"] == "recorded against lens version 1.0", (
        "the notes recorded against version 1.0 did not survive the upgrade"
    )

    want_after = dict(counts_v1, UNANSWERED=1)
    counts_v2 = _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens_arn)["LensReview"]["RiskCounts"],
        lambda c: c == want_after,
        f"the upgraded review's counts never converged on {want_after!r}",
    )
    assert counts_v2 == _histogram(_all_answers(wa, WorkloadId=wid, LensAlias=lens_arn)), (
        f"the upgraded review's counts {counts_v2!r} disagree with its own answers"
    )

    milestones = wa.list_milestones(WorkloadId=wid)["MilestoneSummaries"]
    named = [m for m in milestones if m["MilestoneName"] == upgrade_milestone]
    assert len(named) == 1, (
        f"UpgradeLensReview did not record the milestone it required a name for; milestones are "
        f"{[m['MilestoneName'] for m in milestones]!r}"
    )
    frozen = wa.get_lens_review(
        WorkloadId=wid, LensAlias=lens_arn, MilestoneNumber=named[0]["MilestoneNumber"],
    )["LensReview"]
    assert frozen["LensVersion"] == "1.0", (
        f"the upgrade milestone holds lens version {frozen['LensVersion']!r}, expected the "
        f"pre-upgrade '1.0'"
    )
    assert frozen["RiskCounts"] == counts_v1, (
        f"the upgrade milestone's counts {frozen['RiskCounts']!r} are not the pre-upgrade "
        f"{counts_v1!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
