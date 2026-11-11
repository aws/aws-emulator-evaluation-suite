"""merge-branch-tag-name-rejected."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote

from behavioral_harness import tags

CHECK = "merge-branch-tag-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codecommit"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MergeBranchesByFastForward with a git tag name as targetBranch is rejected with
    BranchNameIsTagNameException; the same merge with a real branch name succeeds."""
    from fidelity_tests_runner import require_tools

    require_tools("git")

    cc = ctx.client("codecommit")
    iam = ctx.client("iam")

    repo_name = ctx.unique_name("sim2real-behav-mbtnr-")
    cc.create_repository(repositoryName=repo_name, tags={"sim2real": "mbtnr"})
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo_name))

    put1 = cc.put_file(
        repositoryName=repo_name, branchName="main", fileContent=b"init", filePath="README.md"
    )
    base_commit = put1["commitId"]
    # A second, real branch used later as the positive control.
    cc.create_branch(repositoryName=repo_name, branchName="feature", commitId=base_commit)
    put2 = cc.put_file(
        repositoryName=repo_name,
        branchName="feature",
        fileContent=b"change",
        filePath="feature.txt",
        parentCommitId=base_commit,
    )
    feature_commit = put2["commitId"]

    repo_meta = cc.get_repository(repositoryName=repo_name)["repositoryMetadata"]
    repo_arn = repo_meta["Arn"]
    clone_url = repo_meta["cloneUrlHttp"]

    # No CodeCommit API creates a tag, so push a real one over git with IAM git credentials.
    user_name = ctx.unique_name("sim2real-behav-mbtnr-user-")
    try:
        iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"cannot create a throwaway IAM user to obtain CodeCommit git credentials: {exc}"
        )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "codecommit-git-access"
    policy_document = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["codecommit:GitPull", "codecommit:GitPush"],
                    "Resource": repo_arn,
                }
            ],
        }
    )
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=policy_document
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    try:
        cred = iam.create_service_specific_credential(
            UserName=user_name, ServiceName="codecommit.amazonaws.com"
        )["ServiceSpecificCredential"]
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"cannot create CodeCommit service-specific git credentials for the IAM user: {exc}"
        )
    cred_id = cred["ServiceSpecificCredentialId"]
    ctx.on_cleanup(
        lambda: iam.delete_service_specific_credential(
            UserName=user_name, ServiceSpecificCredentialId=cred_id
        )
    )

    target_url, route_headers = ctx.endpoint_route(clone_url)
    scheme, sep, rest = target_url.partition("://")
    authed_url = (
        f"{scheme}{sep}{quote(cred['ServiceUserName'], safe='')}:"
        f"{quote(cred['ServicePassword'], safe='')}@{rest}"
    )

    git_env = dict(ctx.subprocess_env())
    git_env["GIT_TERMINAL_PROMPT"] = "0"
    if route_headers:
        git_env.update(
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="http.extraHeader",
            GIT_CONFIG_VALUE_0=f"Host: {route_headers['Host']}",
        )

    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = os.path.join(tmp, "repo")

        # IAM credential propagation is eventually consistent (documented latency up
        # to a few seconds for newly created service-specific credentials), so poll
        # the clone itself rather than sleeping a fixed duration before trying once.
        clone_result = _poll_until(
            lambda: subprocess.run(
                ["git", "clone", "--quiet", authed_url, repo_dir],
                capture_output=True,
                text=True,
                env=git_env,
            ),
            lambda r: r.returncode == 0,
            timeout_s=60.0,
            interval_s=5.0,
            cleanup_between_tries=lambda: shutil.rmtree(repo_dir, ignore_errors=True),
        )
        if clone_result is None or clone_result.returncode != 0:
            stderr = clone_result.stderr if clone_result is not None else "timed out"
            raise AssertionError(
                f"could not clone the CodeCommit repo over git with fresh IAM "
                f"credentials within 60s: {stderr}"
            )

        subprocess.run(
            ["git", "-C", repo_dir, "config", "user.email", "sim2real@example.com"], check=True
        )
        subprocess.run(["git", "-C", repo_dir, "config", "user.name", "sim2real"], check=True)
        tag_name = "not-a-branch-tag"
        subprocess.run(
            ["git", "-C", repo_dir, "tag", "-a", tag_name, "-m", "test tag", "HEAD"], check=True
        )
        push = subprocess.run(
            ["git", "-C", repo_dir, "push", "--quiet", "origin", tag_name],
            capture_output=True,
            text=True,
            env=git_env,
        )
        if push.returncode != 0:
            raise AssertionError(f"could not push the git tag to CodeCommit: {push.stderr}")

    # sourceCommitSpecifier/destinationCommitSpecifier accept any ref (branch, tag,
    # commit id, HEAD) per the API docs, so a tag there resolves fine. targetBranch,
    # however, is documented as "the branch where the merge is applied" -- it must
    # literally be a branch, so pointing it at a tag name is what triggers the
    # exception.
    code, message = _error(
        lambda: cc.merge_branches_by_fast_forward(
            repositoryName=repo_name,
            sourceCommitSpecifier="feature",
            destinationCommitSpecifier=f"refs/tags/{tag_name}",
        )
    )
    assert code == "BranchNameIsTagNameException", f"destSpecifier got={code!r}"
    assert message == (
        "The specified branch name is not valid. Branch names cannot be tag names. "
        "Provide a valid branch name, and then try again."
    ), message

    # Effect absent: main's head did not move because of the rejected tag-as-branch merge.
    branch = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert branch["commitId"] == base_commit, (
        f"main moved to {branch['commitId']!r} after a rejected merge; expected it to stay "
        f"at {base_commit!r}"
    )

    # Positive control: fast-forwarding using a real branch name succeeds and actually
    # advances the destination branch head.
    merged = cc.merge_branches_by_fast_forward(
        repositoryName=repo_name,
        sourceCommitSpecifier="feature",
        destinationCommitSpecifier="main",
        targetBranch="main",
    )
    assert merged["commitId"] == feature_commit, (
        f"fast-forward merge returned commitId={merged['commitId']!r}, expected the feature "
        f"branch tip {feature_commit!r}"
    )
    advanced = cc.get_branch(repositoryName=repo_name, branchName="main")["branch"]
    assert advanced["commitId"] == feature_commit, (
        f"main is at {advanced['commitId']!r} after the legitimate fast-forward, expected it "
        f"advanced to {feature_commit!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, cleanup_between_tries=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        if cleanup_between_tries is not None:
            cleanup_between_tries()
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
