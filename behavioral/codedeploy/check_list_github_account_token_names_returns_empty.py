"""list-github-account-token-names-returns-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-github-account-token-names-returns-empty"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGitHubAccountTokenNames succeeds with a list of token-name strings that a repeat call returns
    unchanged, rather than raising OperationNotSupportedException, and an application the check creates still
    appears in ListApplications.
    """
    cd = ctx.client("codedeploy")

    # The token list is account-wide and no API call can add to it, so the check grades its
    # shape (a list of token-name strings) rather than any exact content the account holds.
    resp = cd.list_git_hub_account_token_names()
    tokens = resp["tokenNameList"]
    assert isinstance(tokens, list), f"expected a tokenNameList list, got {tokens!r}"
    assert all(isinstance(t, str) for t in tokens), f"expected token-name strings, got {tokens!r}"

    # consistency: repeating the call yields the same set, not a transient blip
    resp_repeat = cd.list_git_hub_account_token_names()
    assert sorted(resp_repeat["tokenNameList"]) == sorted(tokens), (
        f"expected the same tokenNameList on repeat, got {resp_repeat['tokenNameList']!r} "
        f"after {tokens!r}"
    )

    # positive control: an application this check creates is visible through an independent,
    # unrelated control-plane read, proving the client/credentials/service are genuinely live and
    # not merely returning an empty shape that any broken target would also produce
    app_name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=app_name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    names: set[str] = set()
    paginator = cd.get_paginator("list_applications")
    for page in paginator.paginate():
        names.update(page.get("applications", []))
    assert app_name in names, f"{app_name} not found in ListApplications result {sorted(names)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

