"""git-push-over-https-is-readable-through-the-api."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from urllib.parse import quote

from behavioral_harness import tags

CHECK = "git-push-over-https-is-readable-through-the-api"
GROUP = 'data-plane'
SERVICES = ['codecommit']


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A commit the git client pushed over the HTTPS clone URL is readable through the API
    with the commit id and tree id git computed locally and byte-identical blobs, since
    git computes object ids before the push and the service must store exactly those.
    """
    from fidelity_tests_runner import require_tools

    require_tools("git")

    cc = ctx.client("codecommit")
    iam = ctx.client("iam")

    repo = ctx.unique_name("sim2real-behav-ccgit-")
    meta = cc.create_repository(repositoryName=repo, tags={"sim2real": "ccgit"})["repositoryMetadata"]
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))
    repo_arn, clone_url = meta["Arn"], meta["cloneUrlHttp"]

    pre_push_head = cc.put_file(
        repositoryName=repo, branchName="main", filePath="README.md",
        fileContent=b"seeded through the API\n", commitMessage="seed",
    )["commitId"]

    # A throwaway IAM user is the only way to obtain HTTPS Git credentials: they are
    # minted per user by create_service_specific_credential.
    user = ctx.unique_name("sim2real-behav-ccgit-u-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": "ccgit"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    policy_name = "codecommit-git-access"
    iam.put_user_policy(
        UserName=user, PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["codecommit:GitPull", "codecommit:GitPush"],
                "Resource": repo_arn,
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName=policy_name))
    cred = iam.create_service_specific_credential(
        UserName=user, ServiceName="codecommit.amazonaws.com")["ServiceSpecificCredential"]
    cred_id = cred["ServiceSpecificCredentialId"]
    ctx.on_cleanup(lambda: iam.delete_service_specific_credential(
        UserName=user, ServiceSpecificCredentialId=cred_id))

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

    work = tempfile.mkdtemp(prefix="sim2real-ccgit-")
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    clone_dir = os.path.join(work, "clone")

    # A brand-new service-specific credential is not usable immediately and IAM exposes no condition
    # to poll, so the bounded retry sits on the first use of the credential. A clone that never
    # succeeds is a failure.
    clone = _retry_git(
        lambda: subprocess.run(["git", "clone", "--quiet", authed_url, clone_dir],
                               capture_output=True, text=True, env=git_env, timeout=120),
        between=lambda: shutil.rmtree(clone_dir, ignore_errors=True),
        timeout_s=150.0,
    )
    assert clone.returncode == 0, (
        f"git clone of {clone_url!r} exited {clone.returncode} after retrying for the "
        f"credential-propagation window; stderr={clone.stderr[-600:]!r}"
    )

    branch = _git(clone_dir, "symbolic-ref", "--short", "HEAD")
    assert branch == "main", f"the clone checked out branch {branch!r}, expected 'main'"
    assert _git(clone_dir, "rev-parse", "HEAD") == pre_push_head, (
        f"the clone's HEAD is {_git(clone_dir, 'rev-parse', 'HEAD')!r} but the branch was "
        f"seeded at {pre_push_head!r} through the API -- git and the API disagree on the tip"
    )

    # Three payload shapes that separate byte length from character length and from any
    # text-encoding round trip, written through git rather than through PutFile.
    payloads = {
        "ascii.txt": b"pushed by the git client\n",
        "unicode.txt": "café — über\n".encode("utf-8"),
        "binary.dat": bytes(range(256)),
    }
    for name, content in payloads.items():
        with open(os.path.join(clone_dir, name), "wb") as fh:
            fh.write(content)
    _git(clone_dir, "config", "user.email", "sim2real@example.com")
    _git(clone_dir, "config", "user.name", "sim2real")
    _git(clone_dir, "add", "-A")
    _git(clone_dir, "commit", "-q", "-m", "three payload shapes over the git transport")

    local_head = _git(clone_dir, "rev-parse", "HEAD")
    local_tree = _git(clone_dir, "rev-parse", "HEAD^{tree}")

    push = subprocess.run(["git", "-C", clone_dir, "push", "--quiet", "origin", "main"],
                          capture_output=True, text=True, env=git_env, timeout=180)
    assert push.returncode == 0, (
        f"git push to CodeCommit exited {push.returncode}; stderr={push.stderr[-800:]!r}"
    )

    # The whole point: the ids git computed locally are the ids the service now serves.
    served = cc.get_branch(repositoryName=repo, branchName="main")["branch"]
    assert served["commitId"] == local_head, (
        f"GetBranch('main') reports {served['commitId']!r}; the git client computed and "
        f"pushed {local_head!r} -- the service stored a different commit object"
    )
    commit = cc.get_commit(repositoryName=repo, commitId=local_head)["commit"]
    assert commit["treeId"] == local_tree, (
        f"GetCommit({local_head}) treeId is {commit['treeId']!r}; git's HEAD^{{tree}} is "
        f"{local_tree!r} -- the service rebuilt the tree instead of storing the pushed one"
    )
    assert commit["parents"] == [pre_push_head], (
        f"GetCommit({local_head}) parents {commit['parents']!r}, expected exactly "
        f"[{pre_push_head!r}] -- the pushed commit must sit on the API-seeded tip"
    )

    # And the bytes survived the pack round trip unaltered.
    for name, content in payloads.items():
        got = cc.get_file(repositoryName=repo, commitSpecifier=local_head, filePath=name)
        assert got["fileContent"] == content, (
            f"GetFile({name}) after the push returned {len(got['fileContent'])} bytes "
            f"{got['fileContent'][:40]!r}; git pushed {len(content)} bytes {content[:40]!r}"
        )
        assert got["fileSize"] == len(content), (
            f"GetFile({name}) fileSize {got['fileSize']} != pushed byte length {len(content)}"
        )
        blob = cc.get_blob(repositoryName=repo, blobId=got["blobId"])
        assert blob["content"] == content, (
            f"GetBlob({got['blobId']}) for {name} returned {len(blob['content'])} bytes "
            f"{blob['content'][:40]!r}; git pushed {len(content)} bytes {content[:40]!r}"
        )
        # git's own id for the same bytes, computed by the local binary, not by us.
        assert _git(clone_dir, "hash-object", "-t", "blob", "--", name) == got["blobId"], (
            f"git hash-object for {name} is "
            f"{_git(clone_dir, 'hash-object', '-t', 'blob', '--', name)!r}; the API reports "
            f"blobId {got['blobId']!r}"
        )


def _git(cwd: str, *args: str) -> str:
    """Run a local, credential-free git command and return its stripped stdout."""
    r = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"git {' '.join(args)} exited {r.returncode}: {r.stderr[-400:]!r}"
    return r.stdout.strip()


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
