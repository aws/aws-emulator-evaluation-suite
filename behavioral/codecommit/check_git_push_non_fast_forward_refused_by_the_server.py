"""git-push-non-fast-forward-refused-by-the-server."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "git-push-non-fast-forward-refused-by-the-server"
GROUP = 'concurrency'
SERVICES = ['codecommit']


@tags("axis:rejection", "concern:data-plane", "dp:native", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Two clones commit on main: the ref advances once, the stale push is refused in
    receive-pack, and the loser lands after rebasing, so a ref moves only from what the
    pusher last saw. Pushes are serialised, so this is a staleness refusal, not a race.
    """
    from fidelity_tests_runner import require_tools

    require_tools("git")

    cc = ctx.client("codecommit")
    iam = ctx.client("iam")

    repo = ctx.unique_name("sim2real-behav-ccnff-")
    meta = cc.create_repository(repositoryName=repo, tags={"sim2real": "ccnff"})["repositoryMetadata"]
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    seed = cc.put_file(repositoryName=repo, branchName="main", filePath="README.md",
                       fileContent=b"seed\n", commitMessage="seed")["commitId"]

    user = ctx.unique_name("sim2real-behav-ccnff-u-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": "ccnff"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    policy_name = "codecommit-git-access"
    iam.put_user_policy(
        UserName=user, PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["codecommit:GitPull", "codecommit:GitPush"],
                "Resource": meta["Arn"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=policy_name))
    cred = iam.create_service_specific_credential(
        UserName=user, ServiceName="codecommit.amazonaws.com")["ServiceSpecificCredential"]
    cred_id = cred["ServiceSpecificCredentialId"]
    ctx.on_cleanup(lambda: iam.delete_service_specific_credential(
        UserName=user, ServiceSpecificCredentialId=cred_id))

    clone_url, route_headers = ctx.endpoint_route(meta["cloneUrlHttp"])
    scheme, sep, rest = clone_url.partition("://")
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

    work = tempfile.mkdtemp(prefix="sim2real-ccnff-")
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))

    # The first clone also serves as the bounded retry over credential propagation: IAM
    # exposes no condition that reports a new service-specific credential as usable, so
    # the first use of it is the only observable. A clone that never succeeds is a
    # FAILURE -- git is present and the endpoint resolves.
    winner = os.path.join(work, "winner")
    first = _retry_git(
        lambda: subprocess.run(["git", "clone", "--quiet", authed_url, winner],
                               capture_output=True, text=True, env=git_env, timeout=120),
        between=lambda: shutil.rmtree(winner, ignore_errors=True),
        timeout_s=150.0,
    )
    assert first.returncode == 0, (
        f"git clone exited {first.returncode} after the credential-propagation window; "
        f"stderr={first.stderr[-600:]!r}"
    )
    loser = os.path.join(work, "loser")
    second = subprocess.run(["git", "clone", "--quiet", authed_url, loser],
                            capture_output=True, text=True, env=git_env, timeout=120)
    assert second.returncode == 0, (
        f"the second git clone exited {second.returncode}; stderr={second.stderr[-600:]!r}"
    )
    for d in (winner, loser):
        _git(d, "config", "user.email", "sim2real@example.com")
        _git(d, "config", "user.name", "sim2real")
        assert _git(d, "rev-parse", "HEAD") == seed, (
            f"clone {os.path.basename(d)} starts at {_git(d, 'rev-parse', 'HEAD')!r}, "
            f"expected the seeded tip {seed!r} -- both clones must start from one ref"
        )

    _commit(winner, "winner.txt", b"written by the winning clone\n", "winner")
    _commit(loser, "loser.txt", b"written by the losing clone\n", "loser")
    winner_head = _git(winner, "rev-parse", "HEAD")
    loser_head = _git(loser, "rev-parse", "HEAD")
    assert winner_head != loser_head, "both clones produced the same commit id"

    accepted = subprocess.run(["git", "-C", winner, "push", "origin", "main"],
                              capture_output=True, text=True, env=git_env, timeout=180)
    assert accepted.returncode == 0, (
        f"the first push exited {accepted.returncode}; stderr={accepted.stderr[-800:]!r}"
    )

    # Break exactly one thing: the loser's parent is now stale. Nothing else differs --
    # same credential, same ref, objects that were acceptable a moment ago.
    refused = subprocess.run(["git", "-C", loser, "push", "origin", "main"],
                             capture_output=True, text=True, env=git_env, timeout=180)
    assert refused.returncode == 1, (
        f"the stale push exited {refused.returncode}, expected 1; "
        f"stderr={refused.stderr[-900:]!r} stdout={refused.stdout[-400:]!r}"
    )
    # git prints the rejection marker and, because the loser's remote-tracking ref is
    # stale, "(fetch first)" as the reason.
    assert "! [rejected]" in refused.stderr, (
        f"the stale push did not report a rejected ref; stderr={refused.stderr!r}"
    )
    assert "(fetch first)" in refused.stderr, (
        f"the stale push was rejected but not as a stale-ref refusal; "
        f"stderr={refused.stderr!r}"
    )

    # Effect absent, read through the API rather than through git: the ref advanced
    # exactly once, and the loser's blob was never stored under it.
    tip = cc.get_branch(repositoryName=repo, branchName="main")["branch"]
    assert tip["commitId"] == winner_head, (
        f"GetBranch('main') is {tip['commitId']!r} after the refused push; the accepted "
        f"push left it at {winner_head!r} -- the ref must not advance for a stale pusher"
    )
    try:
        cc.get_file(repositoryName=repo, commitSpecifier=winner_head, filePath="loser.txt")
        raise AssertionError(
            f"loser.txt resolves at {winner_head} even though its push was refused"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "FileDoesNotExistException", (
            f"GetFile on the refused path raised {code!r} at the accepted tip"
        )
        message = exc.response["Error"].get("Message")
        assert message == "Could not find path loser.txt", message

    # Positive control, in this file: rebase onto the winner and the identical objects
    # are accepted. This is what proves the refusal was about staleness and not about
    # the credential, the ref name or the payload.
    rebase = subprocess.run(["git", "-C", loser, "pull", "--rebase", "--quiet", "origin", "main"],
                            capture_output=True, text=True, env=git_env, timeout=180)
    assert rebase.returncode == 0, (
        f"git pull --rebase exited {rebase.returncode}; stderr={rebase.stderr[-800:]!r}"
    )
    rebased_head = _git(loser, "rev-parse", "HEAD")
    assert rebased_head != loser_head, (
        f"the rebase left HEAD at {rebased_head!r}; it must be rewritten onto the winner"
    )
    retry = subprocess.run(["git", "-C", loser, "push", "origin", "main"],
                           capture_output=True, text=True, env=git_env, timeout=180)
    assert retry.returncode == 0, (
        f"the rebased push exited {retry.returncode}; stderr={retry.stderr[-800:]!r}"
    )

    advanced = cc.get_branch(repositoryName=repo, branchName="main")["branch"]
    assert advanced["commitId"] == rebased_head, (
        f"GetBranch('main') is {advanced['commitId']!r} after the rebased push, expected "
        f"the rebased head {rebased_head!r}"
    )
    rebased_commit = cc.get_commit(repositoryName=repo, commitId=rebased_head)["commit"]
    assert rebased_commit["parents"] == [winner_head], (
        f"the rebased commit's parents are {rebased_commit['parents']!r}, expected "
        f"exactly [{winner_head!r}] -- history must be linear, not a silent merge"
    )
    for path, content in (("winner.txt", b"written by the winning clone\n"),
                          ("loser.txt", b"written by the losing clone\n")):
        got = cc.get_file(repositoryName=repo, commitSpecifier=rebased_head, filePath=path)
        assert got["fileContent"] == content, (
            f"GetFile({path}) at the rebased tip returned {got['fileContent']!r}, "
            f"expected {content!r} -- both clones' work must survive"
        )


def _git(cwd: str, *args: str) -> str:
    """Run a local, credential-free git command and return its stripped stdout."""
    r = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"git {' '.join(args)} exited {r.returncode}: {r.stderr[-400:]!r}"
    return r.stdout.strip()


def _commit(cwd: str, name: str, content: bytes, message: str) -> None:
    with open(os.path.join(cwd, name), "wb") as fh:
        fh.write(content)
    _git(cwd, "add", "-A")
    _git(cwd, "commit", "-q", "-m", message)


def _retry_git(attempt, *, between, timeout_s: float, interval_s: float = 5.0):
    """Retry a git subprocess until it exits 0 or the window closes.

    IAM exposes no condition that reports a service-specific credential as usable, so
    the first use of it is the only observable, and it is retried rather than slept on.
    """
    deadline = time.monotonic() + timeout_s
    result = attempt()
    while result.returncode != 0 and time.monotonic() < deadline:
        between()
        time.sleep(interval_s)
        result = attempt()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
