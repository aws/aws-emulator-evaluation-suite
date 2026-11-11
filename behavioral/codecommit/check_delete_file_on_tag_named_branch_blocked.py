"""delete-file-on-tag-named-branch-blocked."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "delete-file-on-tag-named-branch-blocked"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteFile with a branchName that names only a git tag (pushed over git) raises
    BranchDoesNotExistException and leaves the tagged commit, while DeleteFile on the branch removes the
    file."""
    require_tools("git", "aws")

    codecommit = ctx.client("codecommit")
    repo_name = ctx.unique_name("sim2real-behav-repo-")
    repo = codecommit.create_repository(
        repositoryName=repo_name, tags={"sim2real": "cctagblk"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda: codecommit.delete_repository(repositoryName=repo_name))
    clone_url = repo["cloneUrlHttp"]

    work_dir = tempfile.mkdtemp(prefix="sim2real-codecommit-")
    ctx.on_cleanup(lambda: shutil.rmtree(work_dir, ignore_errors=True))

    env = dict(ctx.subprocess_env())
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.setdefault("HOME", os.path.expanduser("~"))

    _run(["git", "init"], work_dir, env)
    _run(["git", "checkout", "-b", "main"], work_dir, env)
    _run(["git", "config", "user.email", "sim2real@example.com"], work_dir, env)
    _run(["git", "config", "user.name", "sim2real"], work_dir, env)
    _run(
        ["git", "config", "credential.helper", "!aws codecommit credential-helper $@"],
        work_dir,
        env,
    )
    _run(["git", "config", "credential.UseHttpPath", "true"], work_dir, env)

    file_path = os.path.join(work_dir, "hello.txt")
    with open(file_path, "w") as f:
        f.write("hello world\n")
    _run(["git", "add", "hello.txt"], work_dir, env)
    _run(["git", "commit", "-m", "initial commit"], work_dir, env)
    commit_id = _run(["git", "rev-parse", "HEAD"], work_dir, env).strip()

    _run(["git", "remote", "add", "origin", clone_url], work_dir, env)
    _run(["git", "push", "origin", "main"], work_dir, env)

    tag_name = ctx.unique_name("sim2real-behav-tag-")
    _run(["git", "tag", tag_name], work_dir, env)
    _run(
        ["git", "push", "origin", f"refs/tags/{tag_name}:refs/tags/{tag_name}"],
        work_dir,
        env,
    )

    # DeleteFile with branchName set to the tag name must be rejected.
    code, message = _error(
        lambda: codecommit.delete_file(
            repositoryName=repo_name,
            branchName=tag_name,
            filePath="hello.txt",
            parentCommitId=commit_id,
        )
    )
    assert code == "BranchDoesNotExistException", code
    expected = "The specified branch does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the file is still present at the tip of "main".
    still_there = codecommit.get_file(repositoryName=repo_name, filePath="hello.txt")
    assert still_there["commitId"] == commit_id, (
        f"expected file tip commitId {commit_id!r} unchanged by the rejected "
        f"DeleteFile, got {still_there['commitId']!r}"
    )

    # Positive control: DeleteFile against the real branch name succeeds.
    result = codecommit.delete_file(
        repositoryName=repo_name,
        branchName="main",
        filePath="hello.txt",
        parentCommitId=commit_id,
    )
    assert result["commitId"] != commit_id, (
        f"expected DeleteFile against the real branch to advance the tip past "
        f"{commit_id!r}, got the same commitId back"
    )
    code_after, message_after = _error(
        lambda: codecommit.get_file(repositoryName=repo_name, filePath="hello.txt")
    )
    assert code_after == "FileDoesNotExistException", code_after
    expected_after = "Could not find path hello.txt"
    assert message_after == expected_after, (
        f"expected message {expected_after!r}, got {message_after!r}"
    )


def _run(cmd, cwd, env):
    result = subprocess.run(
        cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command {cmd} failed (rc={result.returncode}):\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout


def _error(fn):
    """Call fn(); return its error (code, message). A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
