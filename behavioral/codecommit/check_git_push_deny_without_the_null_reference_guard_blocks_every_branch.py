"""git-push-deny-without-the-null-reference-guard-blocks-every-branch."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags

CHECK = "git-push-deny-without-the-null-reference-guard-blocks-every-branch"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]

_ASSUME_TIMEOUT_S = 45.0
# Each IAM policy edit needs its own propagation window; a shorter one would misread a
# not-yet-propagated edit as the final behaviour.
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
    """Dropping the `Null: {"codecommit:References": "false"}` clause from a GitPush Deny
    widens it from one branch to every branch, and restoring the clause narrows it back.

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

    repo = ctx.unique_name("sim2real-behav-ccnull-")
    meta = cc.create_repository(
        repositoryName=repo, tags={"sim2real": "ccnull"}
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

    role_name = ctx.unique_name("sim2real-behav-ccnull-r-")
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
        Tags=[{"Key": "sim2real", "Value": "ccnull"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "codecommit-null-guard"
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )

    allow = {
        "Sid": "AllowGit",
        "Effect": "Allow",
        "Action": ["codecommit:GitPull", "codecommit:GitPush"],
        "Resource": repo_arn,
    }

    def _deny(with_null_guard: bool) -> dict:
        """The documented Deny, optionally missing the one clause under test."""
        condition: dict = {
            "StringEqualsIfExists": {"codecommit:References": ["refs/heads/main"]}
        }
        if with_null_guard:
            condition["Null"] = {"codecommit:References": "false"}
        return {
            "Sid": "DenyPushToMain",
            "Effect": "Deny",
            "Action": ["codecommit:GitPush"],
            "Resource": repo_arn,
            "Condition": condition,
        }

    def _put(statements: list[dict]) -> None:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )

    _put([allow, _deny(with_null_guard=True)])
    creds = _assume(sts, role_arn, ctx.unique_name("ccnull-"), _ASSUME_TIMEOUT_S)
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

    work = tempfile.mkdtemp(prefix="sim2real-ccnull-")
    ctx.on_cleanup(lambda: _rmtree(work))
    clone_dir = str(Path(work) / "clone")

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
            f"git clone of {clone_url} as {role_arn} to succeed -- GitPull is granted, so a "
            "persistent failure means the git endpoint is unreachable for this principal"
        ),
    )
    _git(clone_dir, "config", "user.email", "sim2real@example.com")
    _git(clone_dir, "config", "user.name", "sim2real")
    # CodeCommit's git HEAD symref can track the last branch touched rather than
    # `defaultBranch`, so "feature" may already be checked out; `-B` creates-or-resets.
    _git(clone_dir, "checkout", "-q", "-B", "feature", "--track", "origin/feature")

    _write(clone_dir, "guarded-ok.txt", b"lands while the guarded deny is attached\n")
    _git(clone_dir, "add", "-A")
    _git(clone_dir, "commit", "-q", "-m", "feature commit under the guarded deny")
    guarded_head = _git(clone_dir, "rev-parse", "HEAD")
    _await(
        lambda: _push(clone_dir, "feature", git_env),
        ok=lambda r: r.returncode == 0,
        between=lambda: None,
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="the guarded Deny propagating without blocking the feature branch",
        expectation=(
            "the push to refs/heads/feature to SUCCEED with the DOCUMENTED (Null-guarded) deny "
            "attached -- the guarded policy must not touch other branches, or nothing below "
            "could attribute a wider block to the missing guard"
        ),
    )
    served = cc.get_branch(repositoryName=repo, branchName="feature")["branch"]
    assert served["commitId"] == guarded_head, (
        f"GetBranch('feature') reports {served['commitId']!r}, expected the commit git pushed "
        f"under the guarded deny, {guarded_head!r}"
    )
    # The guarded deny must still deny its own target, or it is a no-op policy.
    _git(clone_dir, "checkout", "-q", "-B", "main", "--track", "origin/main")
    _write(clone_dir, "guarded-blocked.txt", b"must not reach main\n")
    _git(clone_dir, "add", "-A")
    _git(clone_dir, "commit", "-q", "-m", "main commit under the guarded deny")
    blocked_head = _git(clone_dir, "rev-parse", "HEAD")
    _await(
        lambda: _push(clone_dir, "main", git_env),
        ok=lambda r: r.returncode != 0,
        between=lambda: None,
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="the guarded Deny taking effect on its own target ref",
        expectation=(
            "the push to refs/heads/main to be REFUSED by the guarded deny -- a persistent exit "
            "0 means the policy is a no-op, and the widening this check measures would be "
            "unattributable"
        ),
    )
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == seed, (
        f"main advanced despite the guarded deny; expected the seeded tip {seed!r}, "
        f"the refused commit was {blocked_head!r}"
    )

    _put([allow, _deny(with_null_guard=False)])
    feature_before = cc.get_branch(repositoryName=repo, branchName="feature")["branch"][
        "commitId"
    ]
    assert feature_before == guarded_head, (
        f"feature is at {feature_before!r} entering the unguarded leg, expected {guarded_head!r}"
    )
    # Without the Null guard, StringEqualsIfExists is TRUE for receive-pack's keyless discovery
    # call, so every ref is denied (a 403 before any pack data). Enforcement flaps during
    # propagation, so retry a non-mutating --dry-run and demand several consecutive denials.
    _await_stable(
        lambda: _push(clone_dir, "feature", git_env, dry_run=True),
        ok=lambda r: r.returncode != 0,
        stable_count=3,
        between=lambda: None,
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="the unguarded Deny propagating to receive-pack's keyless discovery call",
        expectation=(
            "a --dry-run push to refs/heads/feature to be REFUSED, three times in a row, once "
            "the Null guard is removed and the policy edit has settled -- a dry run never "
            "mutates the ref, so it is safe to retry while waiting, and it exercises the same "
            "keyless discovery call a real push would"
        ),
    )

    _git(clone_dir, "checkout", "-q", "feature")
    _write(clone_dir, "unguarded.txt", b"must not land while the guard is missing\n")
    _git(clone_dir, "add", "-A")
    _git(clone_dir, "commit", "-q", "-m", "feature commit under the UNGUARDED deny")
    unguarded_head = _git(clone_dir, "rev-parse", "HEAD")

    # Attempted exactly once: a retried real push could land during propagation and move the ref.
    unguarded = _push(clone_dir, "feature", git_env)
    assert unguarded.returncode != 0, (
        "the push to refs/heads/feature succeeded immediately after a --dry-run probe "
        "confirmed the unguarded Deny was already active for the identical ref -- the docs "
        "make the Null guard mandatory for a GitPush Deny, so this must be refused. "
        f"stdout={unguarded.stdout!r} stderr={unguarded.stderr[-500:]!r}"
    )
    lowered = unguarded.stderr.lower()
    for stale_token in ("fetch first", "non-fast-forward"):
        assert stale_token not in lowered, (
            f"the unguarded push was refused, but stderr names {stale_token!r} -- that is "
            f"git's staleness refusal, and the local ref was current, so this is the wrong "
            f"mechanism. stderr={unguarded.stderr[-400:]!r}"
        )

    feature_after = cc.get_branch(repositoryName=repo, branchName="feature")["branch"][
        "commitId"
    ]
    assert feature_after == guarded_head, (
        f"feature advanced to {feature_after!r} despite the refused push; expected it to stay "
        f"at {guarded_head!r}. The refused commit was {unguarded_head!r}"
    )

    _put([allow, _deny(with_null_guard=True)])
    assert _git(clone_dir, "rev-parse", "HEAD") == unguarded_head, (
        "local feature moved between the refused and restored pushes, so they are not the "
        "identical call the restore beat requires"
    )
    _await(
        lambda: _push(clone_dir, "feature", git_env),
        ok=lambda r: r.returncode == 0,
        between=lambda: None,
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="the restored Null guard narrowing the Deny back to refs/heads/main",
        expectation=(
            f"the byte-identical push of {unguarded_head} to refs/heads/feature to SUCCEED once "
            "the Null guard is restored -- the widening must be reversible by that one clause"
        ),
    )
    final = cc.get_branch(repositoryName=repo, branchName="feature")["branch"]
    assert final["commitId"] == unguarded_head, (
        f"GetBranch('feature') reports {final['commitId']!r} after the restored push; git "
        f"pushed {unguarded_head!r}"
    )
    commit = cc.get_commit(repositoryName=repo, commitId=unguarded_head)["commit"]
    assert commit["parents"] == [guarded_head], (
        f"GetCommit({unguarded_head}) parents {commit['parents']!r}, expected exactly "
        f"[{guarded_head!r}] -- the once-refused commit must sit on the tip it was built on"
    )
    assert cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"] == seed, (
        f"main advanced to "
        f"{cc.get_branch(repositoryName=repo, branchName='main')['branch']['commitId']!r} "
        f"after the guard was restored; the narrow deny must still hold main at {seed!r}"
    )


def _assume(sts, role_arn: str, session: str, timeout_s: float) -> dict:
    """AssumeRole against a just-created role, retrying AccessDenied until timeout_s."""
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
    """Retry ``attempt`` until ``ok(result)``, then return it; raise with expected vs actual
    on expiry."""
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


def _await_stable(
    attempt,
    *,
    ok,
    stable_count: int,
    between,
    timeout_s: float,
    reason: str,
    expectation: str,
    interval_s: float = 5.0,
):
    """Retry ``attempt`` until ``ok(result)`` holds for ``stable_count`` consecutive calls:
    IAM enforcement can flap during propagation, so one denial does not mean it has settled."""
    deadline = time.monotonic() + timeout_s
    streak = 0
    result = attempt()
    while time.monotonic() < deadline:
        streak = streak + 1 if ok(result) else 0
        if streak >= stable_count:
            return result
        between()
        time.sleep(interval_s)
        result = attempt()
    raise AssertionError(
        f"expected {expectation} within {timeout_s}s while waiting for {reason} (needed "
        f"{stable_count} consecutive, reached a streak of {streak}); the last attempt exited "
        f"{result.returncode} with stdout={result.stdout[-200:]!r} "
        f"stderr={result.stderr[-500:]!r}"
    )


def _git_raw(args: list[str], *, env: dict, timeout: int = 180):
    return subprocess.run(
        ["git", *args], env=env, capture_output=True, text=True, timeout=timeout
    )


def _git(cwd: str, *args: str) -> str:
    r = subprocess.run(
        ["git", "-C", cwd, *args], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, (
        f"local git {' '.join(args)} exited {r.returncode}: {r.stderr[-400:]!r}"
    )
    return r.stdout.strip()


def _push(clone_dir: str, ref: str, env: dict, *, dry_run: bool = False):
    args = [
        "-C",
        clone_dir,
        "-c",
        "credential.helper=!aws codecommit credential-helper $@",
        "-c",
        "credential.UseHttpPath=true",
        "push",
    ]
    if dry_run:
        args.append("--dry-run")
    args += ["origin", f"HEAD:refs/heads/{ref}"]
    return _git_raw(args, env=env)


def _write(clone_dir: str, name: str, content: bytes) -> None:
    (Path(clone_dir) / name).write_bytes(content)


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
