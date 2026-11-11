"""milestone-freezes-answers-while-workload-moves."""
from __future__ import annotations

import time
import uuid
from collections import Counter

from behavioral_harness import tags

CHECK = "milestone-freezes-answers-while-workload-moves"
GROUP = 'milestones'
SERVICES = ['wellarchitected']

_RISKS = ("UNANSWERED", "HIGH", "MEDIUM", "NONE", "NOT_APPLICABLE")


def _poll(fn, want, what, timeout=120.0, interval=1.5):
    """Poll fn() until want(value) holds, then return that value. RiskCounts are derived
    asynchronously, a second or two behind UpdateAnswer, so a count is polled."""
    deadline = time.time() + timeout
    while True:
        value = fn()
        if want(value):
            return value
        if time.time() >= deadline:
            raise AssertionError(f"{what}: never held within {timeout}s; last observed {value!r}")
        time.sleep(interval)


def _all_answers(wa, **kw):
    """ListAnswers has no botocore paginator; the framework lens spans two pages at MaxResults=50."""
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


def _create_workload(ctx, wa, name, description, environment):
    """CreateWorkload + its teardown. AwsRegions is required by the service though the Smithy
    model marks neither AwsRegions nor NonAwsRegions required."""
    out = wa.create_workload(
        WorkloadName=name,
        Description=description,
        Environment=environment,
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


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A milestone keeps the answers, RiskCounts, Description and Environment of its instant while later
    UpdateAnswer and UpdateWorkload calls change the live workload; the same reads differ only by
    MilestoneNumber.
    """
    wa = ctx.client("wellarchitected")
    lens = "wellarchitected"
    wid = _create_workload(
        ctx, wa, ctx.unique_name("sim2real-behav-wa-ms-"), "description-before-milestone",
        "PREPRODUCTION",
    )

    answers = _all_answers(wa, WorkloadId=wid, LensAlias=lens, MaxResults=50)
    total = len(answers)
    target = answers[0]
    qid = target["QuestionId"]
    choice = target["Choices"][0]["ChoiceId"]

    recorded = wa.update_answer(
        WorkloadId=wid, LensAlias=lens, QuestionId=qid, SelectedChoices=[choice],
        Notes="answered before the milestone",
    )["Answer"]
    frozen_risk = recorded["Risk"]
    _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens)["LensReview"]["RiskCounts"],
        lambda c: c["UNANSWERED"] == total - 1,
        f"UNANSWERED never fell to {total - 1} before the milestone was taken",
    )

    milestone = wa.create_milestone(
        WorkloadId=wid, MilestoneName=ctx.unique_name("sim2real-behav-ms-"),
        ClientRequestToken=str(uuid.uuid4()),
    )
    number = milestone["MilestoneNumber"]
    assert number == 1, f"the first milestone of a workload was numbered {number!r}, expected 1"

    # Move the live workload on: unanswer the question and re-describe the workload.
    live_answer = wa.update_answer(
        WorkloadId=wid, LensAlias=lens, QuestionId=qid, SelectedChoices=[],
    )["Answer"]
    assert live_answer["Risk"] == "UNANSWERED", (
        f"clearing the selection left Risk {live_answer['Risk']!r}, expected UNANSWERED"
    )
    wa.update_workload(
        WorkloadId=wid, Description="description-after-milestone", Environment="PRODUCTION",
    )

    frozen = wa.get_answer(
        WorkloadId=wid, LensAlias=lens, QuestionId=qid, MilestoneNumber=number,
    )["Answer"]
    assert frozen["SelectedChoices"] == [choice], (
        f"the milestone's answer reads {frozen['SelectedChoices']!r}, not the [{choice!r}] "
        f"recorded before it — a milestone must not follow the live review"
    )
    assert frozen["Risk"] == frozen_risk, (
        f"the milestone's risk moved to {frozen['Risk']!r}, expected the frozen {frozen_risk!r}"
    )
    live = wa.get_answer(WorkloadId=wid, LensAlias=lens, QuestionId=qid)["Answer"]
    assert live["SelectedChoices"] == [], (
        f"the live answer reads {live['SelectedChoices']!r}, expected the cleared []"
    )

    frozen_counts = wa.get_lens_review(
        WorkloadId=wid, LensAlias=lens, MilestoneNumber=number,
    )["LensReview"]["RiskCounts"]
    assert frozen_counts["UNANSWERED"] == total - 1, (
        f"the milestone's risk counts {frozen_counts!r} do not still hold {total - 1} unanswered"
    )
    assert frozen_counts[frozen_risk] == 1, (
        f"the milestone's risk counts {frozen_counts!r} lost the frozen {frozen_risk!r} answer"
    )
    assert frozen_counts == _histogram(
        _all_answers(wa, WorkloadId=wid, LensAlias=lens, MaxResults=50, MilestoneNumber=number)
    ), f"the milestone's counts {frozen_counts!r} disagree with its own frozen answers"

    live_counts = _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens)["LensReview"]["RiskCounts"],
        lambda c: c["UNANSWERED"] == total,
        f"the live review's UNANSWERED never returned to {total} after the answer was cleared",
    )
    assert live_counts != frozen_counts, (
        f"the live counts and the milestone's counts are both {live_counts!r} — the milestone "
        f"is tracking the live review instead of the instant it was taken"
    )

    snapshot = wa.get_milestone(WorkloadId=wid, MilestoneNumber=number)["Milestone"]
    assert snapshot["MilestoneNumber"] == number, (
        f"GetMilestone returned number {snapshot['MilestoneNumber']!r}, asked for {number!r}"
    )
    snap_workload = snapshot["Workload"]
    assert snap_workload["Description"] == "description-before-milestone", (
        f"the milestone's workload snapshot says Description "
        f"{snap_workload['Description']!r}, expected the pre-milestone value"
    )
    assert snap_workload["Environment"] == "PREPRODUCTION", (
        f"the milestone's workload snapshot says Environment "
        f"{snap_workload['Environment']!r}, expected the pre-milestone PREPRODUCTION"
    )
    current = wa.get_workload(WorkloadId=wid)["Workload"]
    assert current["Description"] == "description-after-milestone", (
        f"the live workload says Description {current['Description']!r}, expected the updated value"
    )
    assert current["Environment"] == "PRODUCTION", (
        f"the live workload says Environment {current['Environment']!r}, expected PRODUCTION"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
