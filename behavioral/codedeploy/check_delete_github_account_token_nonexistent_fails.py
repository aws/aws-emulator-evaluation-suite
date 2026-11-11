"""delete-github-account-token-nonexistent-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-github-account-token-nonexistent-fails"
GROUP = "overly-permissive"
SERVICES = ["codedeploy"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGitHubAccountToken with an empty tokenName is GitHubAccountTokenNameRequiredException.

    As a positive control, deleting a valid but never-registered tokenName succeeds, echoes the
    name, and the name is absent from ListGitHubAccountTokenNames.
    """
    codedeploy = ctx.client("codedeploy")

    # The functionally-required-but-modeled-optional tokenName: an empty string must
    # be rejected, not treated as "no token name supplied and thus a no-op success".
    code, message = _error(lambda: codedeploy.delete_git_hub_account_token(tokenName=""))
    assert code == "GitHubAccountTokenNameRequiredException", f"unexpected code: {code}"
    assert message == "Token name is missing", message

    # Positive control: a syntactically valid but never-registered token name is
    # accepted idempotently (empirically confirmed on real AWS) and echoes the name.
    never_created_token = ctx.unique_name("sim2real-ghtoken-")
    resp = codedeploy.delete_git_hub_account_token(tokenName=never_created_token)
    assert resp["tokenName"] == never_created_token, (
        f"expected echoed tokenName {never_created_token!r}, got {resp.get('tokenName')!r}"
    )

    listing = codedeploy.list_git_hub_account_token_names()
    assert isinstance(listing["tokenNameList"], list), (
        f"expected tokenNameList to be a list, got {listing['tokenNameList']!r}"
    )
    assert never_created_token not in listing["tokenNameList"], (
        f"never-created token {never_created_token!r} unexpectedly present in "
        f"{listing['tokenNameList']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises,
    because an emulator accepting input real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

