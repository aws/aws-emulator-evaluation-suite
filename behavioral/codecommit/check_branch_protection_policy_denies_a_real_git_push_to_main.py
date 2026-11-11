"""branch-protection-policy-denies-a-real-git-push-to-main."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags

CHECK = "branch-protection-policy-denies-a-real-git-push-to-main"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]

#: A freshly created role is not immediately assumable. Bounded, and raises on expiry.
_ASSUME_TIMEOUT_S = 45.0
#: An inline-policy edit propagates eventually; dependent pushes are retried inside this window.
_POLICY_FLIP_TIMEOUT_S = 120.0


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """An IAM Deny on `codecommit:References` refuses a real `git push` to refs/heads/main and
    leaves main's tip untouched, while a push to refs/heads/feature still lands; the
    identical push to main succeeds once the Deny is removed.

    Reference: https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-conditional-branch.html
    """
    from fidelity_tests_runner import require_tools

    require_tools("git", "aws")

    cc = ctx.client("codecommit")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    identity = sts.get_caller_identity()
    account = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    repo = ctx.unique_name("sim2real-behav-ccref-")
    meta = cc.create_repository(
        repositoryName=repo, tags={"sim2real": "ccref"}
    )["repositoryMetadata"]
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))
    repo_arn = meta["Arn"]
    clone_url, route_headers = ctx.endpoint_route(meta["cloneUrlHttp"])

    seed = cc.put_file(
        repositoryName=repo,
        branchName="main",
        filePath="README.md",
        fileContent=b"seeded through the API\n",
        commitMessage="seed",
    )["commitId"]
    cc.create_branch(repositoryName=repo, branchName="feature", commitId=seed)

    # A role, not the caller: the caller must keep enough privilege to read the effect back
    # independently, so the restriction has to live on a second principal.
    role_name = ctx.unique_name("sim2real-behav-ccref-r-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "ccref"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "codecommit-branch-protection"
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )

    def _put(statements: list[dict]) -> None:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )

    allow = {
        "Sid": "AllowGit",
        "Effect": "Allow",
        "Action": ["codecommit:GitPull", "codecommit:GitPush"],
        "Resource": repo_arn,
    }
    # Verbatim the documented branch-protection statement, narrowed to GitPush. The `Null`
    # guard is not optional: the docs state it is REQUIRED in any Deny naming GitPush,
    # "because of the way Git and git-receive-pack work when pushing changes from a local
    # repo to CodeCommit" -- receive-pack makes an authorization call that carries no
    # References key at all.
    deny_main = {
        "Sid": "DenyPushToMain",
        "Effect": "Deny",
        "Action": ["codecommit:GitPush"],
        "Resource": repo_arn,
        "Condition": {
            "StringEqualsIfExists": {"codecommit:References": ["refs/heads/main"]},
            "Null": {"codecommit:References": "false"},
        },
    }

    _put([allow])
    creds = _assume(sts, role_arn, ctx.unique_name("ccref-"), _ASSUME_TIMEOUT_S)
    git_env = dict(ctx.subprocess_env())
    git_env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
    git_env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
    git_env["AWS_SESSION_TOKEN"] = creds["SessionToken"]
    git_env["GIT_TERMINAL_PROMPT"] = "0"
    if route_headers:
        git_env.update(
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="http.extraHeader",
            GIT_CONFIG_VALUE_0=f"Host: {route_headers['Host']}",
        )

    work = tempfile.mkdtemp(prefix="sim2real-ccref-")
    ctx.on_cleanup(lambda: _rmtree(work))
    clone_dir = str(Path(work) / "clone")

    # The clone needs only GitPull, which the Allow grants, and it also proves the assumed
    # role can reach the git endpoint at all -- so a later push failure cannot be blamed on
    # unusable credentials.
    _await(
        lambda: _git_raw(
            [
                "-c",
                "credential.helper=!aws codecommit credential-helper $@",
                "-c",
                "credential.UseHttpPath=true",
                "clone",
                "--quiet",
                clone_url,
                clone_dir,
            ],
            env=git_env,
        ),
        ok=lambda r: r.returncode == 0,
        between=lambda: _rmtree(clone_dir),
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="the assumed role's git credentials becoming usable",
        expectation=(
            f"git clone of {clone_url} as {role_arn} to succeed -- the Allow statement grants "
            "GitPull, so a persistent failure means the git transport is unreachable for this "
            "principal"
        ),
    )
    _git(clone_dir, "config", "user.email", "sim2real@example.com")
    _git(clone_dir, "config", "user.name", "sim2real")

    # CodeCommit's git HEAD can follow the most recently created branch rather than
    # defaultBranch, so `-B` works whichever branch clone checked out.
    _write(clone_dir, "on-feature.txt", b"pushed to the feature branch\n")
    _git(clone_dir, "checkout", "-q", "-B", "feature", "--track", "origin/feature")
    _git(clone_dir, "add", "-A")
    _git(clone_dir, "commit", "-q", "-m", "work on feature")
    feature_head = _git(clone_dir, "rev-parse", "HEAD")
    first = _push(clone_dir, "feature", git_env)
    assert first.returncode == 0, (
        f"the positive control push to refs/heads/feature exited {first.returncode} with the "
        f"Allow-only policy attached; without it nothing below can distinguish a branch-scoped "
        f"deny from a broken principal. stderr={first.stderr[-500:]!r}"
    )
    served = cc.get_branch(repositoryName=repo, branchName="feature")["branch"]
    assert served["commitId"] == feature_head, (
        f"GetBranch('feature') reports {served['commitId']!r} but git pushed "
        f"{feature_head!r}; the control push did not land"
    )

    _put([allow, deny_main])
    main_before = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert main_before == seed, (
        f"main is at {main_before!r} before the deny leg, expected the seeded tip {seed!r}"
    )

    _git(clone_dir, "checkout", "-q", "-B", "main", "--track", "origin/main")

    # The Deny propagates eventually, so a push can still land right after PutRolePolicy.
    # Re-pushing a landed commit is "Everything up-to-date" (exit 0), so each attempt commits
    # fresh content; `state["landed"]` tracks the last commit that actually reached main.
    state: dict = {"landed": seed, "candidate": None}

    def _attempt_denied_push():
        i = state.get("i", 0) + 1
        state["i"] = i
        _write(
            clone_dir,
            f"on-main-{i}.txt",
            f"attempt {i} while the deny is attached -- must not survive if rejected\n".encode(),
        )
        _git(clone_dir, "add", "-A")
        _git(clone_dir, "commit", "-q", "-m", f"work aimed at main, attempt {i}")
        candidate = _git(clone_dir, "rev-parse", "HEAD")
        state["candidate"] = candidate
        r = _push(clone_dir, "main", git_env)
        if r.returncode == 0:
            state["landed"] = candidate
        return r

    refused = _await(
        _attempt_denied_push,
        ok=lambda r: r.returncode != 0,
        between=lambda: None,
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="the Deny statement taking effect for the already-issued session",
        expectation=(
            f"a git push to refs/heads/main to be REFUSED with the documented "
            f"codecommit:References Deny attached to {role_arn} -- each retry pushes a fresh, "
            "previously-unseen commit so a push that lands before propagation finishes cannot "
            "be mistaken for a target that never enforces the Deny; a persistent exit 0 across "
            "the full window means the branch protection is not enforced on the git transport "
            "at all"
        ),
    )
    main_candidate = state["candidate"]
    assert main_candidate != feature_head, (
        "the main-bound commit and the feature commit share an id, so the pushes are not "
        "distinguishable"
    )
    # Must be an authorization refusal, not git's staleness refusal, which names these tokens.
    lowered = refused.stderr.lower()
    for stale_token in ("fetch first", "non-fast-forward"):
        assert stale_token not in lowered, (
            f"the push to main was refused, but stderr names {stale_token!r}, which is git's "
            f"STALENESS refusal, not an authorization refusal -- the ref was current, so this "
            f"is the wrong mechanism. stderr={refused.stderr[-400:]!r}"
        )

    # Earlier attempts may have landed during propagation, so main is compared to the last landed.
    main_after = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert main_after == state["landed"], (
        f"main is at {main_after!r} after the refused push, expected it to stay at "
        f"{state['landed']!r} (the last commit that landed before the Deny took effect). "
        f"The refused push's commit was {main_candidate!r}"
    )
    assert main_candidate not in _all_commit_ids(cc, repo, ["main"]), (
        f"the refused commit {main_candidate!r} is reachable from main; a refused push must "
        f"leave no object on the protected ref"
    )

    # Same policy, same session, different ref: the deny is per-ref, not repository-wide.
    _git(clone_dir, "checkout", "-q", "feature")
    _write(clone_dir, "on-feature-2.txt", b"second feature commit under the deny\n")
    _git(clone_dir, "add", "-A")
    _git(clone_dir, "commit", "-q", "-m", "more work on feature, deny still attached")
    feature_head_2 = _git(clone_dir, "rev-parse", "HEAD")
    scoped = _push(clone_dir, "feature", git_env)
    assert scoped.returncode == 0, (
        f"with the Deny scoped to refs/heads/main attached, the push to refs/heads/feature "
        f"also failed (exit {scoped.returncode}) -- the condition is being evaluated as a "
        f"repository-wide deny instead of per-ref. stderr={scoped.stderr[-500:]!r}"
    )
    served_2 = cc.get_branch(repositoryName=repo, branchName="feature")["branch"]
    assert served_2["commitId"] == feature_head_2, (
        f"GetBranch('feature') reports {served_2['commitId']!r}, expected the second feature "
        f"commit {feature_head_2!r}"
    )

    _put([allow])
    _git(clone_dir, "checkout", "-q", "main")
    assert _git(clone_dir, "rev-parse", "HEAD") == main_candidate, (
        "the local main moved between the refused push and the restored push, so the two "
        "pushes are not the identical call the restore beat requires"
    )
    _await(
        lambda: _push(clone_dir, "main", git_env),
        ok=lambda r: r.returncode == 0,
        between=lambda: None,
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="removal of the Deny statement propagating to the git endpoint",
        expectation=(
            f"the byte-identical push of {main_candidate} to refs/heads/main to SUCCEED once "
            "the Deny is removed -- a permanent refusal is as wrong as no refusal"
        ),
    )
    final = cc.get_branch(repositoryName=repo, branchName="main")["branch"]
    assert final["commitId"] == main_candidate, (
        f"GetBranch('main') reports {final['commitId']!r} after the restored push; git "
        f"pushed {main_candidate!r}"
    )
    commit = cc.get_commit(repositoryName=repo, commitId=main_candidate)["commit"]
    assert commit["parents"] == [state["landed"]], (
        f"GetCommit({main_candidate}) parents {commit['parents']!r}, expected exactly "
        f"[{state['landed']!r}] -- the once-refused commit must sit on the tip it was built "
        "against"
    )


def _assume(sts, role_arn: str, session: str, timeout_s: float) -> dict:
    """AssumeRole against a just-created role, retried until STS sees it; raises on expiry."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session)["Credentials"]
        except ClientError as exc:
            last = exc
            if exc.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException"):
                raise
            time.sleep(2.0)
    raise AssertionError(
        f"AssumeRole({role_arn}) never succeeded within {timeout_s}s; last error {last!r}"
    )


def _await(
    attempt,
    *,
    ok,
    between,
    timeout_s: float,
    reason: str,
    expectation: str,
    interval_s: float = 5.0,
):
    """Retry ``attempt`` until ``ok(result)``, then return it; raises on expiry with the last
    attempt's exit code and output."""
    deadline = time.monotonic() + timeout_s
    result = attempt()
    while not ok(result) and time.monotonic() < deadline:
        between()
        time.sleep(interval_s)
        result = attempt()
    if not ok(result):
        raise AssertionError(
            f"expected {expectation} within {timeout_s}s while waiting for {reason}; the last "
            f"attempt exited {result.returncode} with stdout={result.stdout[-200:]!r} "
            f"stderr={result.stderr[-500:]!r}"
        )
    return result


def _git_raw(args: list[str], *, env: dict, cwd: str | None = None, timeout: int = 180):
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
    )


def _git(cwd: str, *args: str) -> str:
    """A local, credential-free git command. Raises with stderr on non-zero exit."""
    r = subprocess.run(
        ["git", "-C", cwd, *args], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, (
        f"local git {' '.join(args)} exited {r.returncode}: {r.stderr[-400:]!r}"
    )
    return r.stdout.strip()


def _push(clone_dir: str, ref: str, env: dict):
    return _git_raw(
        [
            "-C",
            clone_dir,
            "-c",
            "credential.helper=!aws codecommit credential-helper $@",
            "-c",
            "credential.UseHttpPath=true",
            "push",
            "origin",
            f"HEAD:refs/heads/{ref}",
        ],
        env=env,
    )


def _write(clone_dir: str, name: str, content: bytes) -> None:
    (Path(clone_dir) / name).write_bytes(content)


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def _all_commit_ids(cc, repo: str, branches: list[str]) -> set[str]:
    """Every commit id reachable from ``branches``, walked through GetCommit."""
    seen: set[str] = set()
    frontier = [
        cc.get_branch(repositoryName=repo, branchName=b)["branch"]["commitId"]
        for b in branches
    ]
    while frontier:
        cid = frontier.pop()
        if cid in seen:
            continue
        seen.add(cid)
        frontier.extend(cc.get_commit(repositoryName=repo, commitId=cid)["commit"]["parents"])
    return seen


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
