"""improvements-track-at-risk-answers."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "improvements-track-at-risk-answers"
GROUP = 'lens-review'
SERVICES = ['wellarchitected']


def _poll(fn, want, what, timeout=120.0, interval=1.5):
    """Poll fn() until want(value) holds. The improvement list and the risk counts are both
    derived asynchronously from the answers, a second or two behind UpdateAnswer."""
    deadline = time.time() + timeout
    while True:
        value = fn()
        if want(value):
            return value
        if time.time() >= deadline:
            raise AssertionError(f"{what}: never held within {timeout}s; last observed {value!r}")
        time.sleep(interval)


def _improvements(wa, wid, lens):
    """ListLensReviewImprovements has no botocore paginator; loop the NextToken."""
    out, token = [], None
    while True:
        kw = {"WorkloadId": wid, "LensAlias": lens, "MaxResults": 100}
        if token:
            kw["NextToken"] = token
        page = wa.list_lens_review_improvements(**kw)
        out.extend(page["ImprovementSummaries"])
        token = page.get("NextToken")
        if not token:
            return out


def _lens_json(name, question_ids):
    """A custom lens with authored riskRules, so which questions are AT RISK is decided here and
    not by AWS lens content. Ids must be 3-128 chars of [A-Za-z0-9_]."""
    questions = []
    for qid in question_ids:
        questions.append({
            "id": qid,
            "title": f"Question {qid}",
            "description": "sim2real behavioral check question",
            "choices": [
                {"id": f"{qid}_c1", "title": "First choice",
                 "helpfulResource": {"displayText": "resource"},
                 "improvementPlan": {"displayText": f"improve {qid}_c1"}},
                {"id": f"{qid}_c2", "title": "Second choice",
                 "helpfulResource": {"displayText": "resource"},
                 "improvementPlan": {"displayText": f"improve {qid}_c2"}},
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


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """ListLensReviewImprovements holds exactly the at-risk questions: a MEDIUM answer appears with plans
    for its unselected choice only, and leaves once fully answered or marked not applicable.
    """
    wa = ctx.client("wellarchitected")
    qids = ["sqrisky", "sqspare"]
    lens_arn = wa.import_lens(
        JSONString=_lens_json(ctx.unique_name("sim2real-behav-lens-"), qids),
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
    wid = wa.create_workload(
        WorkloadName=ctx.unique_name("sim2real-behav-wa-imp-"),
        Description="sim2real behavioral check workload",
        Environment="PREPRODUCTION",
        ReviewOwner="sim2real@example.com",
        Lenses=["wellarchitected", lens_arn],
        AwsRegions=[ctx.region],
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=wid, ClientRequestToken=str(uuid.uuid4()))
    )

    assert _improvements(wa, wid, lens_arn) == [], (
        f"a wholly unanswered review already lists improvements: "
        f"{_improvements(wa, wid, lens_arn)!r} — UNANSWERED is not an improvement"
    )

    risky = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqrisky", SelectedChoices=["sqrisky_c1"],
    )["Answer"]
    assert risky["Risk"] == "MEDIUM", (
        f"the first choice alone derived Risk {risky['Risk']!r}, expected MEDIUM"
    )

    listed = _poll(
        lambda: _improvements(wa, wid, lens_arn),
        lambda imps: [i["QuestionId"] for i in imps] == ["sqrisky"],
        "the at-risk question never appeared as the only improvement",
    )
    assert listed[0]["Risk"] == "MEDIUM", (
        f"the improvement reports Risk {listed[0]['Risk']!r}, but the answer's derived risk is MEDIUM"
    )
    assert listed[0]["PillarId"] == "sim2realpillar", (
        f"the improvement is attributed to pillar {listed[0]['PillarId']!r}"
    )
    plans = [p["ChoiceId"] for p in listed[0]["ImprovementPlans"]]
    assert plans == ["sqrisky_c2"], (
        f"the improvement plans cover choices {plans!r}; expected only the unselected 'sqrisky_c2'"
    )
    assert listed[0]["ImprovementPlans"][0]["DisplayText"] == "improve sqrisky_c2", (
        f"the plan text reads {listed[0]['ImprovementPlans'][0]['DisplayText']!r}, not the text "
        f"the imported lens carries for that choice"
    )

    completed = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqrisky",
        SelectedChoices=["sqrisky_c1", "sqrisky_c2"],
    )["Answer"]
    assert completed["Risk"] == "NONE", (
        f"selecting every choice derived Risk {completed['Risk']!r}, expected NONE"
    )
    _poll(
        lambda: _improvements(wa, wid, lens_arn),
        lambda imps: imps == [],
        "the question stayed on the improvement list after it stopped being at risk",
    )

    not_applicable = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqspare", IsApplicable=False,
        Reason="OUT_OF_SCOPE",
    )["Answer"]
    assert not_applicable["Risk"] == "NOT_APPLICABLE", (
        f"a question marked inapplicable derived Risk {not_applicable['Risk']!r}, "
        f"expected NOT_APPLICABLE"
    )
    assert not_applicable["IsApplicable"] is False, (
        f"IsApplicable reads {not_applicable['IsApplicable']!r} after being set to False"
    )
    want = {"UNANSWERED": 0, "HIGH": 0, "MEDIUM": 0, "NONE": 1, "NOT_APPLICABLE": 1}
    _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens_arn)["LensReview"]["RiskCounts"],
        lambda c: c == want,
        f"the review's counts never converged on {want!r} after one answer and one exclusion",
    )
    assert _improvements(wa, wid, lens_arn) == [], (
        f"an inapplicable question was listed as an improvement: "
        f"{_improvements(wa, wid, lens_arn)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
