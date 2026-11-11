"""filter-list-order-stable-across-updates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-list-order-stable-across-updates"
GROUP = "ordering"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """ListFilters returns a stable relative ordering of filter names: updating
    one filter's Rank/Description (without renaming it) does not reorder the
    unrelated filters around it.
    """
    gd = ctx.client("guardduty")
    detector_id = _ensure_detector(ctx)

    # GuardDuty bounds Rank to the current filter count + 1 (it's an insertion
    # position, not an arbitrary priority number). Create sequentially with the
    # next-valid rank (1, then 2, then 3) so each stays within bounds regardless
    # of what else already exists on the detector, giving each filter a
    # distinct, unambiguous position in ListFilters.
    criteria = {"Criterion": {"type": {"Equals": ["Recon:EC2/PortProbeUnprotectedPort"]}}}
    names = [ctx.unique_name(f"sim2real-gd-filt-{tag}-") for tag in ("a", "b", "c")]
    for i, name in enumerate(names, start=1):
        gd.create_filter(
            DetectorId=detector_id,
            Name=name,
            FindingCriteria=criteria,
            Action="NOOP",
            Rank=i,
            Tags={"sim2real-check": CHECK},
        )
        ctx.on_cleanup(lambda n=name: gd.delete_filter(DetectorId=detector_id, FilterName=n))

    before = _relative_order(_list_all_filter_names(gd, detector_id), names)
    # Close the vacuous-pass case: a target that silently drops CreateFilter (or
    # returns an ever-empty ListFilters) would make before == after trivially,
    # by both being empty. Require all three to actually be visible first.
    assert set(before) == set(names), (
        f"expected all three created filters visible via ListFilters before the "
        f"update, got {before} for created names {names}"
    )

    # Unrelated update: change only the Description of the middle filter,
    # leaving its Rank (and everyone else's) untouched. If ordering is driven
    # by Rank, this must not reorder anything.
    gd.update_filter(DetectorId=detector_id, FilterName=names[1], Description="updated description")

    after = _relative_order(_list_all_filter_names(gd, detector_id), names)

    assert before == after, (
        f"relative order of unrelated filters changed after an unrelated "
        f"UpdateFilter (Description-only) call: before={before}, after={after}"
    )


def _ensure_detector(ctx) -> str:
    from botocore.exceptions import ClientError

    gd = ctx.client("guardduty")
    try:
        detector_id = gd.create_detector(Enable=True)["DetectorId"]
        created = True
    except ClientError as e:
        if e.response["Error"]["Code"] != "BadRequestException":
            raise
        ids = gd.list_detectors().get("DetectorIds", [])
        if not ids:
            raise
        detector_id = ids[0]
        created = False
    if created:
        ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


def _list_all_filter_names(gd, detector_id: str) -> list[str]:
    names: list[str] = []
    token = None
    while True:
        kwargs = {"DetectorId": detector_id, "MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        resp = gd.list_filters(**kwargs)
        names.extend(resp.get("FilterNames", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _relative_order(full_list: list[str], subset: list[str]) -> list[str]:
    subset_set = set(subset)
    return [name for name in full_list if name in subset_set]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
