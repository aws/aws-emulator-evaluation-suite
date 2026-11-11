"""reference-condition-key-denies-api-writes-to-a-protected-branch."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "reference-condition-key-denies-api-writes-to-a-protected-branch"
GROUP = "overly-permissive"
SERVICES = ["codecommit"]

_ASSUME_TIMEOUT_S = 45.0
_POLICY_FLIP_TIMEOUT_S = 90.0


@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """The documented `codecommit:References` Deny on refs/heads/main does not gate PutFile,
    DeleteFile or MergeBranchesByThreeWay: all three land on main as if the Deny were absent.

    Reference: https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-conditional-branch.html
    """
    cc = ctx.client("codecommit")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    identity = sts.get_caller_identity()
    account = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    repo = ctx.unique_name("sim2real-behav-ccapiref-")
    repo_arn = cc.create_repository(
        repositoryName=repo, tags={"sim2real": "ccapiref"}
    )["repositoryMetadata"]["Arn"]
    ctx.on_cleanup(lambda: cc.delete_repository(repositoryName=repo))

    # The first write to a new repository can find its aws/codecommit key not yet available.
    seed = _retry_call(
        lambda: cc.put_file(
            repositoryName=repo,
            branchName="main",
            filePath="README.md",
            fileContent=b"seeded through the API\n",
            commitMessage="seed",
        ),
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="the repository's encryption key becoming available",
        codes=("EncryptionKeyUnavailableException",),
    )["commitId"]
    cc.create_branch(repositoryName=repo, branchName="feature", commitId=seed)
    # A divergent commit on feature so the three-way merge has real work to do.
    feature_tip = cc.put_file(
        repositoryName=repo,
        branchName="feature",
        filePath="feature-only.txt",
        fileContent=b"only on feature\n",
        parentCommitId=seed,
        commitMessage="feature work",
    )["commitId"]
    # A file on main for the DeleteFile leg to aim at.
    main_tip = cc.put_file(
        repositoryName=repo,
        branchName="main",
        filePath="deletable.txt",
        fileContent=b"the delete leg targets this\n",
        parentCommitId=seed,
        commitMessage="add a deletable file on main",
    )["commitId"]

    role_name = ctx.unique_name("sim2real-behav-ccapiref-r-")
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
        Tags=[{"Key": "sim2real", "Value": "ccapiref"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "codecommit-api-branch-protection"
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )

    allow = {
        "Sid": "AllowRepoWork",
        "Effect": "Allow",
        "Action": [
            "codecommit:GetBranch",
            "codecommit:GetFile",
            "codecommit:GetFolder",
            "codecommit:GetCommit",
            "codecommit:GetMergeOptions",
            "codecommit:GetMergeConflicts",
            "codecommit:ListBranches",
            "codecommit:PutFile",
            "codecommit:DeleteFile",
            "codecommit:MergeBranchesByThreeWay",
        ],
        "Resource": repo_arn,
    }
    # The documented statement narrowed to the three API actions; the `Null` guard is kept because
    # it is part of the documented form.
    deny_main = {
        "Sid": "DenyWritesToMain",
        "Effect": "Deny",
        "Action": [
            "codecommit:PutFile",
            "codecommit:DeleteFile",
            "codecommit:MergeBranchesByThreeWay",
        ],
        "Resource": repo_arn,
        "Condition": {
            "StringEqualsIfExists": {"codecommit:References": ["refs/heads/main"]},
            "Null": {"codecommit:References": "false"},
        },
    }

    def _put_policy(statements: list[dict]) -> None:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )

    _put_policy([allow])
    creds = _assume(sts, role_arn, ctx.unique_name("ccapiref-"), _ASSUME_TIMEOUT_S)
    restricted = ctx.client(
        "codecommit",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # Positive control on the unprotected branch, as the restricted role.
    control_body = b"written by the restricted role on feature\n"
    control = _retry_call(
        lambda: restricted.put_file(
            repositoryName=repo,
            branchName="feature",
            filePath="from-role.txt",
            fileContent=control_body,
            parentCommitId=feature_tip,
            commitMessage="restricted role writes to feature",
        ),
        timeout_s=_POLICY_FLIP_TIMEOUT_S,
        reason="the Allow statement propagating to the assumed session",
    )
    feature_tip = control["commitId"]
    # Independent read by the unrestricted caller.
    control_read = cc.get_file(
        repositoryName=repo, commitSpecifier="feature", filePath="from-role.txt"
    )
    assert control_read["fileContent"] == control_body, (
        f"GetFile('feature','from-role.txt') returned {control_read['fileContent']!r}, "
        f"expected the {len(control_body)} bytes the restricted role wrote, {control_body!r}"
    )

    # Attach the documented Deny.
    _put_policy([allow, deny_main])
    main_before = cc.get_branch(repositoryName=repo, branchName="main")["branch"]["commitId"]
    assert main_before == main_tip, (
        f"main is at {main_before!r} entering the deny leg, expected {main_tip!r}"
    )

    # The Deny is inert against these actions; each call is issued once with no retry-on-denial, so
    # real enforcement cannot be retried into "eventually succeeded".
    put_result = restricted.put_file(
        repositoryName=repo,
        branchName="main",
        filePath="landed-with-deny-attached.txt",
        fileContent=b"codecommit:References does not gate PutFile\n",
        parentCommitId=main_tip,
        commitMessage="restricted role writes to main with the documented Deny attached",
    )
    main_tip = put_result["commitId"]
    assert main_tip != main_before, (
        f"PutFile on refs/heads/main reported commitId {main_tip!r}, the same tip it was "
        f"built on -- no commit was created"
    )
    landed = cc.get_file(
        repositoryName=repo, commitSpecifier="main", filePath="landed-with-deny-attached.txt"
    )
    assert landed["fileContent"] == b"codecommit:References does not gate PutFile\n", (
        f"GetFile('main','landed-with-deny-attached.txt') returned {landed['fileContent']!r} "
        f"after a PutFile the documented Deny was supposed to refuse"
    )

    put_tip = main_tip
    delete_result = restricted.delete_file(
        repositoryName=repo,
        branchName="main",
        filePath="deletable.txt",
        parentCommitId=main_tip,
    )
    main_tip = delete_result["commitId"]
    assert main_tip != put_tip, (
        f"DeleteFile on refs/heads/main reported commitId {main_tip!r}, the same tip it was "
        f"built on -- no commit was created"
    )
    assert (
        _error(
            lambda: cc.get_file(
                repositoryName=repo, commitSpecifier="main", filePath="deletable.txt"
            )
        )
        == ("FileDoesNotExistException", "Could not find path deletable.txt")
    ), (
        "DeleteFile on refs/heads/main, issued by the restricted role with the documented "
        "Deny attached, did not remove the file -- GetFile at main still serves it"
    )

    delete_tip = main_tip
    merge_result = restricted.merge_branches_by_three_way(
        repositoryName=repo,
        sourceCommitSpecifier="feature",
        destinationCommitSpecifier="main",
        targetBranch="main",
    )
    main_tip = merge_result["commitId"]
    assert main_tip != delete_tip, (
        f"MergeBranchesByThreeWay(targetBranch='main') reported commitId {main_tip!r}, the "
        f"same tip it was built on -- no merge commit was created"
    )
    merged = cc.get_file(
        repositoryName=repo, commitSpecifier="main", filePath="feature-only.txt"
    )
    assert merged["fileContent"] == b"only on feature\n", (
        f"GetFile('main','feature-only.txt') returned {merged['fileContent']!r} after "
        f"MergeBranchesByThreeWay(targetBranch='main') with the documented Deny attached; "
        f"the merge was expected to land feature's content on main despite the Deny"
    )

    final = cc.get_branch(repositoryName=repo, branchName="main")["branch"]
    assert final["commitId"] == main_tip, (
        f"GetBranch('main') reports {final['commitId']!r} but the last of the three calls "
        f"made with the Deny attached created {main_tip!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The (code, message) ``fn`` raised. RAISES on unexpected success, never returns a sentinel."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        "the deleted file is still readable at main -- DeleteFile did not take effect"
    )


def _assume(sts, role_arn: str, session: str, timeout_s: float) -> dict:
    """AssumeRole against a just-created role. Raises on expiry -- never a skip."""
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


#: A just-assumed session can fail with AccessDenied while the Allow propagates, and with
#: UnrecognizedClientException while CodeCommit does not yet recognise the STS session token.
_TRANSIENT_SESSION_CODES = ("AccessDenied", "AccessDeniedException", "UnrecognizedClientException")


def _retry_call(
    fn, *, timeout_s: float, reason: str, interval_s: float = 3.0,
    codes: tuple[str, ...] = _TRANSIENT_SESSION_CODES,
):
    """Retry ``fn`` while it fails with one of ``codes`` (default: a fresh session not yet usable).

    Used only where success is the expected outcome.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response["Error"]["Code"] not in codes:
                raise
            time.sleep(interval_s)
    raise AssertionError(
        f"the call was still failing after {timeout_s}s waiting for {reason}; last error {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
