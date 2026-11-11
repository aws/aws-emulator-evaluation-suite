"""delete-github-account-token-nonexistent-is-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-github-account-token-nonexistent-is-noop"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGitHubAccountToken on a never-created token succeeds (twice) and echoes the tokenName
    instead of raising GitHubAccountTokenDoesNotExistException, and the token is never listed."""
    # There is no API to create a GitHub token; it is only linked via the console OAuth flow.
    cd = ctx.client("codedeploy")

    token_name = ctx.unique_name("sim2real-gh-token-")
    resp = cd.delete_git_hub_account_token(tokenName=token_name)
    assert resp["tokenName"] == token_name, f"expected echoed tokenName {token_name!r}, got {resp.get('tokenName')!r}"

    resp_repeat = cd.delete_git_hub_account_token(tokenName=token_name)
    assert resp_repeat["tokenName"] == token_name, (
        f"repeat delete: expected echoed tokenName {token_name!r}, got {resp_repeat.get('tokenName')!r}"
    )

    apps = cd.list_applications()
    assert isinstance(apps["applications"], list), f"expected a list, got {apps.get('applications')!r}"

    # A delete that secretly registered the token would only show up in this listing.
    listing = cd.list_git_hub_account_token_names()
    assert token_name not in listing["tokenNameList"], (
        f"expected {token_name!r} absent from tokenNameList, found it: {listing['tokenNameList']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

