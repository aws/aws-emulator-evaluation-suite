"""batch-describe-merge-conflicts-agrees-with-the-per-path-reads."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-describe-merge-conflicts-agrees-with-the-per-path-reads"
GROUP = "data-plane"
SERVICES = ["codecommit"]

#: Pinned identically across every call so the two operations' responses are comparable.
_MERGE_OPTION = "THREE_WAY_MERGE"
_DETAIL = "LINE_LEVEL"
# maxMergeHunks above 10 is rejected with InvalidMaxMergeHunksException on both operations.
_MAX_HUNKS = 10


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """BatchDescribeMergeConflicts returns, for every conflicting path and no clean one, exactly
    the conflict detail DescribeMergeConflicts returns per path, and its file paging obeys the
    union law.

    Reference: https://docs.aws.amazon.com/codecommit/latest/APIReference/API_BatchDescribeMergeConflicts.html
    """
    cc = ctx.client("codecommit")

    repo = ctx.unique_name("sim2real-behav-ccbatch-")
    cc.create_repository(repositoryName=repo, tags={"sim2real": "ccbatch"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    conflicting = ["alpha.txt", "beta.txt", "gamma.txt"]
    clean = "clean.txt"

    # One base commit carrying all four files. Single-line bodies keep every conflict to one
    # hunk, so neither operation's hunk paging engages and the details stay comparable.
    base = cc.create_commit(
        repositoryName=repo,
        branchName="main",
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="base for all four paths",
        putFiles=[
            {"filePath": p, "fileContent": f"base body of {p}\n".encode()}
            for p in [*conflicting, clean]
        ],
    )["commitId"]
    cc.create_branch(repositoryName=repo, branchName="feature", commitId=base)

    # Both sides edit the same single line of each conflicting path -> a content conflict each.
    dest_tip = cc.create_commit(
        repositoryName=repo,
        branchName="main",
        parentCommitId=base,
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="destination edits",
        putFiles=[
            {"filePath": p, "fileContent": f"DESTINATION body of {p}\n".encode()}
            for p in conflicting
        ],
    )["commitId"]
    # The feature side edits the same three lines AND adds a path the destination never
    # touched, which must merge cleanly and must therefore NOT appear as a conflict.
    source_tip = cc.create_commit(
        repositoryName=repo,
        branchName="feature",
        parentCommitId=base,
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="source edits plus one clean change",
        putFiles=[
            *[
                {"filePath": p, "fileContent": f"SOURCE body of {p}\n".encode()}
                for p in conflicting
            ],
            {"filePath": clean, "fileContent": b"changed on the source side only\n"},
        ],
    )["commitId"]
    assert len({base, dest_tip, source_tip}) == 3, (
        f"the three commits are not distinct: {base!r} {dest_tip!r} {source_tip!r}"
    )

    common = {
        "repositoryName": repo,
        "destinationCommitSpecifier": dest_tip,
        "sourceCommitSpecifier": source_tip,
        "mergeOption": _MERGE_OPTION,
        "conflictDetailLevel": _DETAIL,
    }

    # ---- The summary view. ----
    summary = cc.get_merge_conflicts(**common)
    assert summary["mergeable"] is False, (
        f"GetMergeConflicts reports mergeable={summary['mergeable']!r} for two branches that "
        f"both rewrote the only line of {len(conflicting)} shared files; expected False"
    )
    summary_paths = {m["filePath"] for m in summary["conflictMetadataList"]}
    assert summary_paths == set(conflicting), (
        f"GetMergeConflicts reports conflicting paths {sorted(summary_paths)!r}, expected "
        f"exactly {sorted(conflicting)!r} -- {clean!r} was changed on one side only and must "
        f"merge cleanly"
    )

    # ---- The batch view, unpaged. ----
    batch = cc.batch_describe_merge_conflicts(**common, maxMergeHunks=_MAX_HUNKS)
    assert batch["errors"] == [], (
        f"BatchDescribeMergeConflicts reports errors {batch['errors']!r} for three well-formed "
        f"conflicting paths in an unpaged request; expected none"
    )
    batch_by_path = {c["conflictMetadata"]["filePath"]: c for c in batch["conflicts"]}
    assert set(batch_by_path) == set(conflicting), (
        f"BatchDescribeMergeConflicts reports paths {sorted(batch_by_path)!r}, expected exactly "
        f"{sorted(conflicting)!r}. A target that returns only the first conflict, or that "
        f"reports every changed path including {clean!r}, fails here and passes every "
        f"single-path conflict read"
    )
    assert len(batch["conflicts"]) == len(conflicting), (
        f"BatchDescribeMergeConflicts returned {len(batch['conflicts'])} conflict entries for "
        f"{len(conflicting)} distinct paths; a duplicated path would collapse in the map above"
    )
    for field, expected in (
        ("destinationCommitId", dest_tip),
        ("sourceCommitId", source_tip),
        ("baseCommitId", base),
    ):
        assert batch[field] == expected, (
            f"BatchDescribeMergeConflicts reports {field} {batch[field]!r}, expected {expected!r}"
        )
        assert summary[field] == expected, (
            f"GetMergeConflicts reports {field} {summary[field]!r}, expected {expected!r}"
        )

    # ---- The agreement law: batch detail == per-path detail, for every path. ----
    for path in conflicting:
        per_path = cc.describe_merge_conflicts(
            **common, filePath=path, maxMergeHunks=_MAX_HUNKS
        )
        assert batch_by_path[path]["conflictMetadata"] == per_path["conflictMetadata"], (
            f"for {path!r}, BatchDescribeMergeConflicts reports conflictMetadata "
            f"{batch_by_path[path]['conflictMetadata']!r} but DescribeMergeConflicts reports "
            f"{per_path['conflictMetadata']!r} for the identical mergeOption "
            f"{_MERGE_OPTION!r} and conflictDetailLevel {_DETAIL!r}. The batch path must not "
            f"re-run the merge under different defaults"
        )
        assert batch_by_path[path]["mergeHunks"] == per_path["mergeHunks"], (
            f"for {path!r}, the batch and per-path mergeHunks differ: "
            f"{batch_by_path[path]['mergeHunks']!r} vs {per_path['mergeHunks']!r}"
        )
        assert per_path["destinationCommitId"] == dest_tip, (
            f"DescribeMergeConflicts({path}) reports destinationCommitId "
            f"{per_path['destinationCommitId']!r}, expected {dest_tip!r}"
        )
        # The detail must actually describe a conflict, not an empty agreement.
        assert per_path["conflictMetadata"]["contentConflict"] is True, (
            f"DescribeMergeConflicts({path}) reports contentConflict "
            f"{per_path['conflictMetadata']['contentConflict']!r}; both sides rewrote the only "
            f"line of the file, so this is a content conflict"
        )
        assert any(h.get("isConflict") for h in per_path["mergeHunks"]), (
            f"DescribeMergeConflicts({path}) returned {len(per_path['mergeHunks'])} hunks and "
            f"none is marked isConflict"
        )

    # ---- The union law over file paging. ----
    pages = []
    token = None
    while True:
        kwargs = dict(common, maxMergeHunks=_MAX_HUNKS, maxConflictFiles=1)
        if token:
            kwargs["nextToken"] = token
        page = cc.batch_describe_merge_conflicts(**kwargs)
        assert len(page["conflicts"]) <= 1, (
            f"page {len(pages) + 1} returned {len(page['conflicts'])} conflicts with "
            f"maxConflictFiles=1; a target that ignores the cap breaks every paging client"
        )
        pages.append([c["conflictMetadata"]["filePath"] for c in page["conflicts"]])
        token = page.get("nextToken")
        if not token:
            break
        assert len(pages) <= len(conflicting) + 1, (
            f"file paging did not terminate after {len(pages)} pages for "
            f"{len(conflicting)} conflicting paths; pages so far: {pages!r}"
        )
    flat = [p for page in pages for p in page]
    assert sorted(flat) == sorted(conflicting), (
        f"paging with maxConflictFiles=1 yielded {flat!r} across {len(pages)} pages; the union "
        f"must be exactly {sorted(conflicting)!r} -- no path missing and none repeated"
    )
    assert len(flat) == len(set(flat)), (
        f"paging returned a duplicate path: {flat!r}"
    )

    # ---- The filePaths filter narrows to exactly what was asked for. ----
    only = conflicting[1]
    narrowed = cc.batch_describe_merge_conflicts(
        **common, maxMergeHunks=_MAX_HUNKS, filePaths=[only]
    )
    assert [c["conflictMetadata"]["filePath"] for c in narrowed["conflicts"]] == [only], (
        f"filePaths=[{only!r}] returned "
        f"{[c['conflictMetadata']['filePath'] for c in narrowed['conflicts']]!r}, expected "
        f"exactly [{only!r}]"
    )
    assert narrowed["errors"] == [], (
        f"the filePaths-narrowed request reports errors {narrowed['errors']!r}, expected none"
    )
    assert narrowed["conflicts"][0]["conflictMetadata"] == batch_by_path[only][
        "conflictMetadata"
    ], (
        f"the filePaths-narrowed conflictMetadata for {only!r} differs from the unfiltered one: "
        f"{narrowed['conflicts'][0]['conflictMetadata']!r} vs "
        f"{batch_by_path[only]['conflictMetadata']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
