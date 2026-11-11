"""branch-name-is-tag-name-rejected."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from behavioral_harness import tags

CHECK = "branch-name-is-tag-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MergeBranchesByThreeWay with a targetBranch that exists only as a git tag raises
    BranchDoesNotExistException and leaves main unchanged, while the tag works as a commit specifier
    for a merge into main."""
    from fidelity_tests_runner import require_tools

    require_tools("git", "aws")

    cc = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-cc-repo-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    commit1 = cc.create_commit(
        repositoryName=repo_name,
        branchName="main",
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="initial commit",
        putFiles=[{"filePath": "README.md", "fileContent": b"hello"}],
    )["commitId"]
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=commit1)
    cc.create_commit(
        repositoryName=repo_name,
        branchName="feature",
        parentCommitId=commit1,
        authorName="sim2real",
        email="sim2real@example.com",
        commitMessage="feature work",
        putFiles=[{"filePath": "feature.txt", "fileContent": b"feature"}],
    )

    tag_name = ctx.unique_name("sim2real-cc-tag-")
    clone_url, clone_headers = ctx.endpoint_route(
        cc.get_repository(repositoryName=repo_name)["repositoryMetadata"]["cloneUrlHttp"]
    )
    env = ctx.subprocess_env()

    workdir = tempfile.mkdtemp(prefix="sim2real-cc-git-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    clone_dir = os.path.join(workdir, "repo")
    try:
        _run_git(["clone", clone_url, clone_dir], env, cwd=workdir, headers=clone_headers)
        _run_git(["tag", tag_name, "main"], env, cwd=clone_dir)
        _run_git(["push", "origin", tag_name], env, cwd=clone_dir, headers=clone_headers)
    except subprocess.CalledProcessError as e:
        raise AssertionError(
            "could not push a git tag to the CodeCommit HTTPS git endpoint via the "
            f"'aws codecommit credential-helper' - stderr: {e.stderr!r}"
        )

    # The tag itself is NOT a valid targetBranch: it has no corresponding head ref,
    # so a merge result cannot be applied there.
    code, message = _error(lambda: cc.merge_branches_by_three_way(
        repositoryName=repo_name,
        sourceCommitSpecifier="feature",
        destinationCommitSpecifier="main",
        targetBranch=tag_name,
    ))
    assert code == "BranchDoesNotExistException", f"unexpected code: {code}"
    expected_message = f"The target branch reference refs/heads/{tag_name} does not exist"
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # effect absent: no branch with the tag's name was created, main untouched
    branches = cc.list_branches(repositoryName=repo_name)["branches"]
    assert tag_name not in branches, (
        f"expected no branch named {tag_name!r} to exist after the rejected merge, "
        f"got branches={branches!r}"
    )
    main_untouched = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert main_untouched["commitId"] == commit1, (
        f"expected main to stay at {commit1!r} after the rejected merge, "
        f"got {main_untouched['commitId']!r}"
    )

    # positive control: the SAME tag name is a perfectly valid commit specifier for
    # source/destination as long as an explicit, real targetBranch is given -- the
    # rejection above is specifically about targetBranch, not about tags in general.
    merge_via_tag = cc.merge_branches_by_three_way(
        repositoryName=repo_name,
        sourceCommitSpecifier="feature",
        destinationCommitSpecifier=tag_name,
        targetBranch="main",
    )
    assert merge_via_tag["commitId"], (
        f"expected merge_branches_by_three_way using {tag_name!r} as "
        "destinationCommitSpecifier to succeed and return a commitId, got "
        f"{merge_via_tag!r}"
    )
    main_final = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert main_final["commitId"] == merge_via_tag["commitId"] != commit1, (
        f"expected main to advance to the merge commit {merge_via_tag['commitId']!r} "
        f"(and away from {commit1!r}), got {main_final['commitId']!r}"
    )


def _run_git(args, env, cwd, headers=None):
    cred_helper = "!aws codecommit credential-helper $@"
    cmd = [
        "git",
        "-c", f"credential.helper={cred_helper}",
        "-c", "credential.UseHttpPath=true",
        *(arg for k, v in (headers or {}).items() for arg in ("-c", f"http.extraHeader={k}: {v}")),
        *args,
    ]
    subprocess.run(cmd, cwd=cwd, env=env, check=True, capture_output=True, text=True)


def _error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
