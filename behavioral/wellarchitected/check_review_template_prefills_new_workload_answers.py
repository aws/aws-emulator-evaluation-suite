"""review-template-prefills-new-workload-answers."""
from __future__ import annotations

import time
import uuid
from collections import Counter

from behavioral_harness import tags

CHECK = "review-template-prefills-new-workload-answers"
GROUP = 'review-templates'
SERVICES = ['wellarchitected']

_RISKS = ("UNANSWERED", "HIGH", "MEDIUM", "NONE", "NOT_APPLICABLE")


def _poll(fn, want, what, timeout=120.0, interval=1.5):
    """Poll fn() until want(value) holds. RiskCounts are derived asynchronously from the answers
    (measured ~1.7 s behind UpdateAnswer on real AWS), so a count is polled and never read once."""
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


def _all_template_answers(wa, arn, lens):
    """ListReviewTemplateAnswers has no botocore paginator either."""
    out, token = [], None
    while True:
        kw = {"TemplateArn": arn, "LensAlias": lens, "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        page = wa.list_review_template_answers(**kw)
        out.extend(page["AnswerSummaries"])
        token = page.get("NextToken")
        if not token:
            return out


def _histogram(answers):
    counts = Counter(a["Risk"] for a in answers)
    return {r: counts.get(r, 0) for r in _RISKS}


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A workload created from a review template gets the template's lens and its one recorded answer
    (same selection, a derived Risk), every other question stays UNANSWERED, and RiskCounts equals the
    histogram of the copied answers.
    """
    wa = ctx.client("wellarchitected")
    lens = "wellarchitected"

    template_name = ctx.unique_name("sim2real-behav-rt-")
    arn = wa.create_review_template(
        TemplateName=template_name,
        Description="sim2real behavioral check review template",
        Lenses=[lens],
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["TemplateArn"]
    ctx.on_cleanup(lambda: wa.delete_review_template(
        TemplateArn=arn, ClientRequestToken=str(uuid.uuid4()),
    ))

    template_answers = _all_template_answers(wa, arn, lens)
    total = len(template_answers)
    assert total > 1, (
        f"the template's lens review holds {total} questions; the check needs more than one so "
        f"that an unanswered question can be distinguished from a prefilled one"
    )
    unanswered = [a for a in template_answers if a["AnswerStatus"] == "UNANSWERED"]
    assert len(unanswered) == total, (
        f"a freshly created review template already has {total - len(unanswered)} answered "
        f"questions; nothing was recorded on it yet"
    )

    target = template_answers[0]
    qid = target["QuestionId"]
    choice = target["Choices"][0]["ChoiceId"]
    other_qid = template_answers[1]["QuestionId"]

    recorded = wa.update_review_template_answer(
        TemplateArn=arn, LensAlias=lens, QuestionId=qid, SelectedChoices=[choice],
        Notes="recorded on the review template",
    )["Answer"]
    assert recorded["SelectedChoices"] == [choice], (
        f"the template answer reads {recorded['SelectedChoices']!r}, expected [{choice!r}]"
    )
    _poll(
        lambda: {
            a["QuestionId"]: a["AnswerStatus"] for a in _all_template_answers(wa, arn, lens)
        },
        lambda st: st[qid] == "ANSWERED" and st[other_qid] == "UNANSWERED",
        f"the template never reported {qid!r} ANSWERED with {other_qid!r} still UNANSWERED",
    )

    # Lenses is deliberately empty: whatever lens review the workload ends up with came from the
    # template, not from this call.
    wid = wa.create_workload(
        WorkloadName=ctx.unique_name("sim2real-behav-wa-rt-"),
        Description="sim2real behavioral check workload",
        Environment="PREPRODUCTION",
        ReviewOwner="sim2real@example.com",
        Lenses=[],
        ReviewTemplateArns=[arn],
        AwsRegions=[ctx.region],
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=wid, ClientRequestToken=str(uuid.uuid4()))
    )

    reviews = wa.list_lens_reviews(WorkloadId=wid)["LensReviewSummaries"]
    assert [r["LensAlias"] for r in reviews] == [lens], (
        f"the workload's lens reviews are {[r.get('LensAlias') for r in reviews]!r}; the template "
        f"named only {lens!r} and the workload named none"
    )

    prefilled = wa.get_answer(WorkloadId=wid, LensAlias=lens, QuestionId=qid)["Answer"]
    assert prefilled["SelectedChoices"] == [choice], (
        f"the question answered on the template arrived at the workload with selection "
        f"{prefilled['SelectedChoices']!r}, expected [{choice!r}]"
    )
    assert prefilled["Risk"] != "UNANSWERED", (
        f"the prefilled question reports Risk {prefilled['Risk']!r}; a copied selection must carry "
        f"a derived risk"
    )
    untouched = wa.get_answer(WorkloadId=wid, LensAlias=lens, QuestionId=other_qid)["Answer"]
    assert untouched["SelectedChoices"] == [], (
        f"a question the template never answered arrived with selection "
        f"{untouched['SelectedChoices']!r}; the template copied more than it held"
    )
    assert untouched["Risk"] == "UNANSWERED", (
        f"a question the template never answered reports Risk {untouched['Risk']!r}"
    )

    counts = _poll(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens)["LensReview"]["RiskCounts"],
        lambda c: c["UNANSWERED"] == total - 1,
        f"the prefilled workload's UNANSWERED never settled at {total - 1} of {total}",
    )
    assert counts == _histogram(
        _all_answers(wa, WorkloadId=wid, LensAlias=lens, MaxResults=50)
    ), f"the prefilled review's counts {counts!r} disagree with its own answers"
    assert counts[prefilled["Risk"]] >= 1, (
        f"the prefilled answer's risk {prefilled['Risk']!r} is not represented in {counts!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
