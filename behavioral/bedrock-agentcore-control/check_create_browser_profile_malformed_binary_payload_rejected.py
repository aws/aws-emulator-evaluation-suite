"""create-browser-profile-malformed-binary-payload-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-browser-profile-malformed-binary-payload-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBrowserProfile with a name outside [a-zA-Z][a-zA-Z0-9_]{0,47} is refused with ValidationException and
    the exact pattern message and leaves no profile; a pattern-valid name is created READY or SAVING and is listed."""
    client = ctx.client("bedrock-agentcore-control")

    bad_name = "1-not-a-valid-name!"
    code, message = _error_detail(lambda: client.create_browser_profile(name=bad_name))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        f"1 validation error detected: Value '{bad_name}' at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z][a-zA-Z0-9_]{0,47}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no profile was created under the malformed name.
    assert not _profile_name_exists(client, bad_name), (
        f"a profile named {bad_name!r} exists despite the rejected create"
    )

    # Positive control: a pattern-valid name succeeds.
    good_name = _pattern_safe_name(ctx, "sim2realbpvalid")
    created = client.create_browser_profile(name=good_name)
    ctx.on_cleanup(lambda: _best_effort_delete(client, created["profileId"]))
    assert created["status"] in ("READY", "SAVING"), (
        f"expected READY or SAVING for a pattern-valid name, got {created['status']!r}"
    )
    assert _profile_name_exists(client, good_name), (
        f"a profile named {good_name!r} was created but does not appear in list_browser_profiles"
    )


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "b" + safe
    return safe[:48]


def _profile_name_exists(client, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_browser_profiles(**kwargs)
        for item in page.get("profileSummaries", []):
            if item.get("name") == name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


def _best_effort_delete(client, profile_id: str) -> None:
    try:
        client.delete_browser_profile(profileId=profile_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
