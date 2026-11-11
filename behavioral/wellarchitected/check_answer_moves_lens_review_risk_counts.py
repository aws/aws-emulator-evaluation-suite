"""answer-moves-lens-review-risk-counts."""
from __future__ import annotations

import time
import uuid
from collections import Counter

from behavioral_harness import tags

CHECK = "answer-moves-lens-review-risk-counts"
GROUP = 'lens-review'
SERVICES = ['wellarchitected']

_RISKS = ("UNANSWERED", "HIGH", "MEDIUM", "NONE", "NOT_APPLICABLE")


def _poll(fn, want, what, timeout=120.0, interval=1.5):
    """Poll fn() until want(value) holds, then return that value.

    RiskCounts are DERIVED asynchronously: GetLensReview can still report the pre-update
    histogram right after UpdateAnswer returns the new Risk, so every count read is a poll.
    """
    deadline = time.time() + timeout
    while True:
        value = fn()
        if want(value):
            return value
        if time.time() >= deadline:
            raise AssertionError(f"{what}: never held within {timeout}s; last observed {value!r}")
        time.sleep(interval)


def _all_answers(wa, **kw):
    """ListAnswers has no botocore paginator, and the framework lens spans 2 pages at the
    50-row maximum, so the NextToken loop is mandatory rather than defensive."""
    out, token = [], None
    while True:
        page = wa.list_answers(NextToken=token, **kw) if token else wa.list_answers(**kw)
        out.extend(page["AnswerSummaries"])
        token = page.get("NextToken")
        if not token:
            return out


def _histogram(answers):
    """The histogram the service's own per-answer Risk values imply."""
    counts = Counter(a["Risk"] for a in answers)
    return {r: counts.get(r, 0) for r in _RISKS}


def _create_workload(ctx, wa, name):
    """CreateWorkload + its teardown.

    AwsRegions is passed because the SERVICE requires one of AwsRegions/NonAwsRegions while the
    Smithy model marks neither required.
    """
    out = wa.create_workload(
        WorkloadName=name,
        Description="sim2real behavioral check workload",
        Environment="PREPRODUCTION",
        ReviewOwner="sim2real@example.com",
        Lenses=["wellarchitected"],
        AwsRegions=[ctx.region],
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )
    wid = out["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=wid, ClientRequestToken=str(uuid.uuid4()))
    )
    return wid


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Answering one question moves exactly one count from UNANSWERED into the Risk UpdateAnswer reported,
    at the lens level and in that question's pillar only, and RiskCounts stays equal to the histogram
    of ListAnswers.
    """
    wa = ctx.client("wellarchitected")
    wid = _create_workload(ctx, wa, ctx.unique_name("sim2real-behav-wa-risk-"))
    lens = "wellarchitected"

    answers = _all_answers(wa, WorkloadId=wid, LensAlias=lens, MaxResults=50)
    total = len(answers)
    assert total > 0, f"the framework lens review returned {total} answers, expected a question set"
    assert _histogram(answers) == {
        "UNANSWERED": total, "HIGH": 0, "MEDIUM": 0, "NONE": 0, "NOT_APPLICABLE": 0
    }, f"a new lens review was not wholly unanswered: {_histogram(answers)!r}"

    before = wa.get_lens_review(WorkloadId=wid, LensAlias=lens)["LensReview"]
    assert before["RiskCounts"] == _histogram(answers), (
        f"RiskCounts {before['RiskCounts']!r} disagrees with the answer histogram "
        f"{_histogram(answers)!r} on a fresh review"
    )
    pillars_before = {p["PillarId"]: p["RiskCounts"] for p in before["PillarReviewSummaries"]}
    assert sum(c["UNANSWERED"] for c in pillars_before.values()) == total, (
        f"pillar UNANSWERED counts {pillars_before!r} do not sum to the {total} answers"
    )

    target = answers[0]
    qid, pillar_id = target["QuestionId"], target["PillarId"]
    choice = target["Choices"][0]["ChoiceId"]
    updated = wa.update_answer(
        WorkloadId=wid, LensAlias=lens, QuestionId=qid, SelectedChoices=[choice],
    )["Answer"]
    assert updated["SelectedChoices"] == [choice], (
        f"UpdateAnswer recorded SelectedChoices {updated['SelectedChoices']!r}, expected [{choice!r}]"
    )
    risk = updated["Risk"]
    assert risk != "UNANSWERED", (
        f"question {qid!r} still reads UNANSWERED after one choice was selected"
    )

    after = _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens)["LensReview"],
        lambda lr: lr["RiskCounts"]["UNANSWERED"] == total - 1,
        f"lens review UNANSWERED never fell to {total - 1} after answering {qid!r}",
    )
    counts = after["RiskCounts"]
    assert counts[risk] == 1, (
        f"UpdateAnswer reported Risk {risk!r} but the review counts {counts!r} do not put "
        f"exactly one question in that bucket"
    )
    assert sum(counts.values()) == total, (
        f"risk counts {counts!r} sum to {sum(counts.values())}, not the {total} questions in the lens"
    )
    assert counts == _histogram(_all_answers(wa, WorkloadId=wid, LensAlias=lens, MaxResults=50)), (
        f"RiskCounts {counts!r} no longer equals the histogram of the answers it aggregates"
    )

    pillars_after = {p["PillarId"]: p["RiskCounts"] for p in after["PillarReviewSummaries"]}
    assert pillars_after[pillar_id][risk] == 1, (
        f"pillar {pillar_id!r} counts {pillars_after[pillar_id]!r} do not carry the answered "
        f"question's {risk!r}"
    )
    unchanged = {p: c for p, c in pillars_after.items() if p != pillar_id}
    assert unchanged == {p: c for p, c in pillars_before.items() if p != pillar_id}, (
        f"answering a {pillar_id!r} question also moved other pillars: {unchanged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
