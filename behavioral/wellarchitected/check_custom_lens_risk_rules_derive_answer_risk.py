"""custom-lens-risk-rules-derive-answer-risk."""
from __future__ import annotations

import json
import time
import uuid
from collections import Counter

from behavioral_harness import tags

CHECK = "custom-lens-risk-rules-derive-answer-risk"
GROUP = 'custom-lens'
SERVICES = ['wellarchitected']

_RISKS = ("UNANSWERED", "HIGH", "MEDIUM", "NONE", "NOT_APPLICABLE")


def _poll(fn, want, what, timeout=120.0, interval=1.5):
    """Poll fn() until want(value) holds. RiskCounts are derived asynchronously (a second or two
    behind UpdateAnswer), so a count is polled and never read once."""
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
    """A custom lens whose riskRules are authored HERE, so the expected derived risk of every
    selection is known independently of any AWS lens content. Question and choice ids must be
    3-128 characters of [A-Za-z0-9_] — the service rejects a 2-character id."""
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


def _published_lens(ctx, wa, question_ids):
    """Import a custom lens, publish version 1.0, and register its teardown.

    Registered before the workload that consumes it is created, so LIFO deletes the workload
    first and the lens second.
    """
    lens_arn = wa.import_lens(
        JSONString=_lens_json(ctx.unique_name("sim2real-behav-lens-"), question_ids),
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
    return lens_arn


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
    """A custom lens's riskRules derive each answer's Risk (NONE for both choices, MEDIUM for the first
    alone, HIGH for the fallback), and GetLensReview and ListLensReviews report RiskCounts equal to
    the histogram of those answers.
    """
    wa = ctx.client("wellarchitected")
    qids = ["sqnone", "sqmedium", "sqhigh"]
    lens_arn = _published_lens(ctx, wa, qids)
    wid = _create_workload(
        ctx, wa, ctx.unique_name("sim2real-behav-wa-rules-"), ["wellarchitected", lens_arn],
    )

    initial = _all_answers(wa, WorkloadId=wid, LensAlias=lens_arn)
    assert sorted(a["QuestionId"] for a in initial) == sorted(qids), (
        f"the imported lens review holds questions "
        f"{sorted(a['QuestionId'] for a in initial)!r}, expected {sorted(qids)!r}"
    )
    assert _histogram(initial)["UNANSWERED"] == len(qids), (
        f"a fresh custom lens review was not wholly unanswered: {_histogram(initial)!r}"
    )

    # Rule 1: every choice selected -> NO_RISK -> Risk NONE.
    both = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqnone",
        SelectedChoices=["sqnone_c1", "sqnone_c2"],
    )["Answer"]
    assert both["Risk"] == "NONE", (
        f"selecting both choices of a NO_RISK rule derived Risk {both['Risk']!r}, expected NONE"
    )

    # Rule 2: the first choice alone -> MEDIUM_RISK.
    medium = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqmedium", SelectedChoices=["sqmedium_c1"],
    )["Answer"]
    assert medium["Risk"] == "MEDIUM", (
        f"selecting only the first choice of a MEDIUM_RISK rule derived Risk "
        f"{medium['Risk']!r}, expected MEDIUM"
    )
    assert medium["ChoiceAnswers"] == [
        {"ChoiceId": "sqmedium_c1", "Status": "SELECTED", "Reason": "", "Notes": ""}
    ], f"the per-choice answer detail reads {medium['ChoiceAnswers']!r}"

    # Rule 3: a selection matching no rule but `default` -> HIGH_RISK.
    high = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqhigh", SelectedChoices=["sqhigh_c2"],
    )["Answer"]
    assert high["Risk"] == "HIGH", (
        f"a selection matching only the default rule derived Risk {high['Risk']!r}, expected HIGH"
    )

    want = {"UNANSWERED": 0, "HIGH": 1, "MEDIUM": 1, "NONE": 1, "NOT_APPLICABLE": 0}
    counts = _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens_arn)["LensReview"]["RiskCounts"],
        lambda c: c == want,
        f"the custom lens review's risk counts never converged on {want!r}",
    )
    assert counts == _histogram(_all_answers(wa, WorkloadId=wid, LensAlias=lens_arn)), (
        f"RiskCounts {counts!r} disagrees with the histogram of its own answers"
    )

    # The same aggregate must be reported by the per-workload lens-review listing.
    summaries = [
        s for s in wa.list_lens_reviews(WorkloadId=wid)["LensReviewSummaries"]
        if s.get("LensArn") == lens_arn
    ]
    assert len(summaries) == 1, (
        f"ListLensReviews returned {len(summaries)} reviews for the imported lens, expected 1"
    )
    assert summaries[0]["RiskCounts"] == want, (
        f"the lens-review summary reports {summaries[0]['RiskCounts']!r}, expected {want!r}"
    )
    assert summaries[0]["LensVersion"] == "1.0", (
        f"the review is pinned to lens version {summaries[0]['LensVersion']!r}, expected '1.0'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
