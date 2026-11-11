"""disassociate-default-lens-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-default-lens-rejected"
GROUP = 'lens-review'
SERVICES = ['wellarchitected']

_DEFAULT_LENS = "wellarchitected"


def _client_error(fn, what):
    """Return the (code, message) fn() raised. A call that SUCCEEDS is the failure, so this never
    returns a falsy sentinel for it."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"{what}: the call succeeded, but real AWS rejects it")


def _retry_while_locked(fn, what, timeout=60.0, interval=1.5):
    """Call fn(), retrying while the workload is still locked by the mutation before it.

    Real AWS holds a short-lived lock over a workload while a structural change settles: a
    lens association issued straight after a disassociation is rejected with
    ConflictException 'Workload is being operated by another user'. It happens intermittently, so
    the retry keeps the check about what it claims rather than about that race.
    """
    deadline = time.time() + timeout
    while True:
        try:
            return fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            locked = (
                error.get("Code") == "ConflictException"
                and "being operated by another user" in error.get("Message", "")
            )
            if not locked or time.time() >= deadline:
                raise AssertionError(
                    f"{what}: still {error.get('Code')!r} ({error.get('Message')!r}) after "
                    f"{timeout}s"
                ) from exc
            time.sleep(interval)


def _poll(fn, want, what, timeout=120.0, interval=1.5):
    """Poll fn() until want(value) holds, then return that value."""
    deadline = time.time() + timeout
    while True:
        value = fn()
        if want(value):
            return value
        if time.time() >= deadline:
            raise AssertionError(f"{what}: never held within {timeout}s; last observed {value!r}")
        time.sleep(interval)


def _review_keys(wa):
    """The lens identities on a workload's reviews, as AssociateLenses/DisassociateLenses name them.

    `LensAlias` is that identity for both kinds: the short alias for an AWS-published lens and the
    full ARN for a custom one. (`LensArn` is not — the framework lens reports the AWS-owned
    `arn:aws:wellarchitected::aws:lens/wellarchitected` there, which is not what the alias is.)
    ListLensReviews has no botocore paginator.
    """
    def _keys(wid):
        out, token = [], None
        while True:
            kw = {"WorkloadId": wid, "MaxResults": 50}
            if token:
                kw["NextToken"] = token
            page = wa.list_lens_reviews(**kw)
            out.extend(s["LensAlias"] for s in page["LensReviewSummaries"])
            token = page.get("NextToken")
            if not token:
                return out
    return _keys


def _lens_json(name):
    """One pillar, one question, authored riskRules. Ids must be 3-128 chars of [A-Za-z0-9_]."""
    return json.dumps({
        "schemaVersion": "2021-11-01",
        "name": name,
        "description": "sim2real behavioral check lens",
        "pillars": [{
            "id": "sim2realpillar",
            "name": "Sim2Real Pillar",
            "questions": [{
                "id": "sqdrop",
                "title": "Question sqdrop",
                "description": "sim2real behavioral check question",
                "choices": [
                    {"id": "sqdrop_c1", "title": "First choice",
                     "helpfulResource": {"displayText": "resource"},
                     "improvementPlan": {"displayText": "plan"}},
                    {"id": "sqdrop_c2", "title": "Second choice",
                     "helpfulResource": {"displayText": "resource"},
                     "improvementPlan": {"displayText": "plan"}},
                ],
                "riskRules": [
                    {"condition": "sqdrop_c1 && sqdrop_c2", "risk": "NO_RISK"},
                    {"condition": "sqdrop_c1", "risk": "MEDIUM_RISK"},
                    {"condition": "default", "risk": "HIGH_RISK"},
                ],
            }],
        }],
    })


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DisassociateLenses refuses the default wellarchitected lens with ValidationException and the exact
    message, keeping its review; a custom lens detaches, its review then fails with ValidationException,
    and re-attaching restores its recorded answer.
    """
    wa = ctx.client("wellarchitected")
    review_keys = _review_keys(wa)

    lens_arn = wa.import_lens(
        JSONString=_lens_json(ctx.unique_name("sim2real-behav-lens-")),
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["LensArn"]
    ctx.on_cleanup(lambda: wa.delete_lens(
        LensAlias=lens_arn, LensStatus="ALL", ClientRequestToken=str(uuid.uuid4()),
    ))
    wa.create_lens_version(
        LensAlias=lens_arn, LensVersion="1.0", IsMajorVersion=True,
        ClientRequestToken=str(uuid.uuid4()),
    )
    wid = wa.create_workload(
        WorkloadName=ctx.unique_name("sim2real-behav-wa-dis-"),
        Description="sim2real behavioral check workload",
        Environment="PREPRODUCTION",
        ReviewOwner="sim2real@example.com",
        Lenses=[_DEFAULT_LENS, lens_arn],
        AwsRegions=[ctx.region],
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=wid, ClientRequestToken=str(uuid.uuid4()))
    )
    assert sorted(review_keys(wid)) == sorted([_DEFAULT_LENS, lens_arn]), (
        f"the workload's reviews are {sorted(review_keys(wid))!r}, expected the default lens and "
        f"the imported one"
    )

    recorded = wa.update_answer(
        WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqdrop",
        SelectedChoices=["sqdrop_c1"], Notes="recorded before the lens was detached",
    )["Answer"]
    assert recorded["Risk"] == "MEDIUM", (
        f"the first choice alone derived Risk {recorded['Risk']!r}, expected MEDIUM"
    )

    code, message = _client_error(
        lambda: wa.disassociate_lenses(WorkloadId=wid, LensAliases=[_DEFAULT_LENS]),
        f"detaching the default {_DEFAULT_LENS!r} lens from a workload",
    )
    assert code == "ValidationException", (
        f"detaching the default lens failed with {code!r}, expected ValidationException"
    )
    expected = f"[Validation] Cannot disassociate default lens: {_DEFAULT_LENS}."
    assert message == expected, (
        f"detaching the default lens was refused with message {message!r}, expected {expected!r}"
    )
    assert _DEFAULT_LENS in review_keys(wid), (
        f"the refused call removed the default lens anyway; the workload's reviews are "
        f"{review_keys(wid)!r}"
    )

    # Rejecting the default lens must not be a blanket refusal: the same call removes a custom one.
    _retry_while_locked(
        lambda: wa.disassociate_lenses(WorkloadId=wid, LensAliases=[lens_arn]),
        "detaching the custom lens",
    )
    remaining = _poll(
        lambda: review_keys(wid),
        lambda keys: lens_arn not in keys,
        "the detached custom lens still had a review on the workload",
    )
    assert remaining == [_DEFAULT_LENS], (
        f"after detaching the custom lens the workload's reviews are {remaining!r}, expected only "
        f"the default lens"
    )
    gone, gone_message = _client_error(
        lambda: wa.get_lens_review(WorkloadId=wid, LensAlias=lens_arn),
        "reading the review of a lens that was detached from the workload",
    )
    assert gone == "ValidationException", (
        f"reading a detached lens's review failed with {gone!r}; real AWS treats the missing review "
        f"as a ValidationException, not as a ResourceNotFoundException"
    )
    expected = f"[Validation] No lens review for lens alias {lens_arn} was found in workload {wid}."
    assert gone_message == expected, (
        f"reading a detached lens's review was refused with message {gone_message!r}, expected "
        f"{expected!r}"
    )

    # Re-attaching restores the recorded answer rather than a blank review.
    _retry_while_locked(
        lambda: wa.associate_lenses(WorkloadId=wid, LensAliases=[lens_arn]),
        "re-attaching the custom lens",
    )
    _poll(
        lambda: review_keys(wid),
        lambda keys: lens_arn in keys,
        "the re-attached custom lens never regained a review",
    )
    restored = wa.get_answer(WorkloadId=wid, LensAlias=lens_arn, QuestionId="sqdrop")["Answer"]
    assert restored["SelectedChoices"] == ["sqdrop_c1"], (
        f"the re-attached lens's answer reads {restored['SelectedChoices']!r}, expected the "
        f"selection recorded before it was detached"
    )
    assert restored["Notes"] == "recorded before the lens was detached", (
        f"the re-attached lens's notes read {restored['Notes']!r}"
    )
    assert restored["Risk"] == "MEDIUM", (
        f"the restored answer's derived risk is {restored['Risk']!r}, expected MEDIUM"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
