"""unpublished-lens-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unpublished-lens-rejected"
GROUP = 'custom-lens'
SERVICES = ['wellarchitected']


# ===== helpers =====
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

    Real AWS holds a short-lived lock over a workload while a structural change settles: a lens
    association issued straight after another workload mutation is rejected with
    ConflictException 'Workload is being operated by another user'. Measured intermittently, so the
    retry is what keeps this check about the draft/published distinction rather than that race.
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


def _lens_summary(wa, lens_arn):
    """Find our lens in ListLenses, which has no botocore paginator.

    Narrowed to the ARN this check imported: the account may hold other lenses, so the
    assertion is about OUR row and never about the size of the list.
    """
    token = None
    while True:
        kw = {"LensType": "CUSTOM_SELF", "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        page = wa.list_lenses(**kw)
        for summary in page["LensSummaries"]:
            if summary.get("LensArn") == lens_arn:
                return summary
        token = page.get("NextToken")
        if not token:
            return None


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
                "id": "sqdraft",
                "title": "Question sqdraft",
                "description": "sim2real behavioral check question",
                "choices": [
                    {"id": "sqdraft_c1", "title": "First choice",
                     "helpfulResource": {"displayText": "resource"},
                     "improvementPlan": {"displayText": "plan"}},
                    {"id": "sqdraft_c2", "title": "Second choice",
                     "helpfulResource": {"displayText": "resource"},
                     "improvementPlan": {"displayText": "plan"}},
                ],
                "riskRules": [
                    {"condition": "sqdraft_c1 && sqdraft_c2", "risk": "NO_RISK"},
                    {"condition": "sqdraft_c1", "risk": "MEDIUM_RISK"},
                    {"condition": "default", "risk": "HIGH_RISK"},
                ],
            }],
        }],
    })


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """An imported, unpublished custom lens is listed in DRAFT yet GetLens denies it and
    AssociateLenses refuses it with a different error, leaving the workload's lenses untouched;
    after CreateLensVersion publishes it, both calls succeed.
    """
    wa = ctx.client("wellarchitected")
    lens_arn = wa.import_lens(
        JSONString=_lens_json(ctx.unique_name("sim2real-behav-lens-")),
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["LensArn"]
    ctx.on_cleanup(lambda: wa.delete_lens(
        LensAlias=lens_arn, LensStatus="ALL", ClientRequestToken=str(uuid.uuid4()),
    ))

    drafted = _lens_summary(wa, lens_arn)
    assert drafted is not None, (
        f"the imported lens {lens_arn!r} is absent from ListLenses(CUSTOM_SELF); an unpublished "
        f"lens still exists and must be listed"
    )
    assert drafted["LensStatus"] == "DRAFT", (
        f"a lens that has only been imported reads LensStatus {drafted['LensStatus']!r}, "
        f"expected DRAFT"
    )
    assert drafted["LensVersion"] == "DRAFT", (
        f"an unpublished lens reports LensVersion {drafted['LensVersion']!r}; until a version is "
        f"published the listing names no version number, it names 'DRAFT'"
    )

    get_draft, get_draft_message = _client_error(
        lambda: wa.get_lens(LensAlias=lens_arn),
        "reading an imported but unpublished custom lens",
    )
    assert get_draft == "ResourceNotFoundException", (
        f"GetLens on a draft lens failed with {get_draft!r}, expected ResourceNotFoundException"
    )
    lens_id = lens_arn.rsplit("/", 1)[-1]
    expected = f"[ResourceNotFound] LENS with id {lens_id} not found. Lens is not published."
    assert get_draft_message == expected, (
        f"GetLens on a draft lens was refused with message {get_draft_message!r}, expected "
        f"{expected!r}"
    )

    wid = wa.create_workload(
        WorkloadName=ctx.unique_name("sim2real-behav-wa-draft-"),
        Description="sim2real behavioral check workload",
        Environment="PREPRODUCTION",
        ReviewOwner="sim2real@example.com",
        Lenses=["wellarchitected"],
        AwsRegions=[ctx.region],
        ClientRequestToken=str(uuid.uuid4()),
        Tags={"sim2real": CHECK},
    )["WorkloadId"]
    ctx.on_cleanup(
        lambda: wa.delete_workload(WorkloadId=wid, ClientRequestToken=str(uuid.uuid4()))
    )

    associate_draft, associate_draft_message = _client_error(
        lambda: wa.associate_lenses(WorkloadId=wid, LensAliases=[lens_arn]),
        "attaching an unpublished custom lens to a workload",
    )
    assert associate_draft == "ValidationException", (
        f"AssociateLenses with a draft lens failed with {associate_draft!r}, expected "
        f"ValidationException"
    )
    expected = (
        f"[Validation] Failed to get lenses {lens_arn}. User might be not authorized to access "
        f"lens."
    )
    assert associate_draft_message == expected, (
        f"AssociateLenses with a draft lens was refused with message "
        f"{associate_draft_message!r}, expected {expected!r}"
    )
    attached = [
        r.get("LensArn") for r in wa.list_lens_reviews(WorkloadId=wid)["LensReviewSummaries"]
    ]
    assert lens_arn not in attached, (
        f"the refused association still attached the draft lens; the workload's reviews are "
        f"{attached!r}"
    )

    # Positive control: publishing a version is the only difference, and both calls now succeed.
    wa.create_lens_version(
        LensAlias=lens_arn, LensVersion="1.0", IsMajorVersion=True,
        ClientRequestToken=str(uuid.uuid4()),
    )
    published = _poll(
        lambda: _lens_summary(wa, lens_arn),
        lambda s: s is not None and s["LensStatus"] == "PUBLISHED",
        "the lens never reached LensStatus PUBLISHED after CreateLensVersion",
    )
    assert published["LensVersion"] == "1.0", (
        f"the published lens reports version {published.get('LensVersion')!r}, expected '1.0'"
    )
    lens = wa.get_lens(LensAlias=lens_arn)["Lens"]
    assert lens["LensVersion"] == "1.0", (
        f"GetLens now reports version {lens['LensVersion']!r}, expected '1.0'"
    )

    _retry_while_locked(
        lambda: wa.associate_lenses(WorkloadId=wid, LensAliases=[lens_arn]),
        "attaching the published lens",
    )
    _poll(
        lambda: [
            r.get("LensArn") for r in wa.list_lens_reviews(WorkloadId=wid)["LensReviewSummaries"]
        ],
        lambda arns: lens_arn in arns,
        "the published lens never appeared among the workload's lens reviews",
    )
    review = wa.get_lens_review(WorkloadId=wid, LensAlias=lens_arn)["LensReview"]
    assert review["RiskCounts"]["UNANSWERED"] == 1, (
        f"the newly attached one-question review reports counts {review['RiskCounts']!r}, expected "
        f"a single UNANSWERED question"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
