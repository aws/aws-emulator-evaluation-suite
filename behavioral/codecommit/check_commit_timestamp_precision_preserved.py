"""commit-timestamp-precision-preserved."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "commit-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["codecommit"]

# Git-style timestamp: "<epoch-seconds> <+/-HHMM>" (GMT offset), e.g. "1699999999 +0000".
_GIT_TIMESTAMP_RE = re.compile(r"^\d+ [+-]\d{4}$")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Author/committer timestamps on GetCommit are exact and stable across repeated reads."""
    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-cc-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "ccts"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    create_resp = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        putFiles=[{"filePath": "f.txt", "fileContent": b"content"}],
        commitMessage="ts precision test",
        authorName="Jane Doe",
        email="jane@example.com",
    )
    commit_id = create_resp["commitId"]

    first = cc.get_commit(repositoryName=repo_name, commitId=commit_id)["commit"]
    author_date_1 = first["author"]["date"]
    committer_date_1 = first["committer"]["date"]

    assert _GIT_TIMESTAMP_RE.match(author_date_1), f"unexpected author date format: {author_date_1!r}"
    assert _GIT_TIMESTAMP_RE.match(committer_date_1), (
        f"unexpected committer date format: {committer_date_1!r}"
    )

    # A second, independent GetCommit must return byte-identical timestamps: the stored
    # value must not be re-derived/rounded/truncated on each read.
    second = cc.get_commit(repositoryName=repo_name, commitId=commit_id)["commit"]
    assert second["author"]["date"] == author_date_1, (
        f"author date changed across reads: {author_date_1!r} -> {second['author']['date']!r}"
    )
    assert second["committer"]["date"] == committer_date_1, (
        f"committer date changed across reads: {committer_date_1!r} -> {second['committer']['date']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
