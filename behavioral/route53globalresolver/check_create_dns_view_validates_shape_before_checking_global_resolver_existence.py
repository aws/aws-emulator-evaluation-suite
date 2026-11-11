"""create-dns-view-validates-shape-before-checking-global-resolver-existence."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-dns-view-validates-shape-before-checking-global-resolver-existence"
GROUP = "validation-ordering"
SERVICES = ["route53globalresolver"]

_NOT_FOUND_CODE = "GR-ERR00309"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _client(ctx):
    """route53globalresolver serves its control plane only in us-east-2, at an api.aws host
    botocore does not resolve by default; ctx.service_url names that host on real AWS and the
    target's endpoint otherwise."""
    return ctx.client(
        "route53globalresolver",
        region="us-east-2",
        endpoint_url=ctx.service_url("https://route53globalresolver.us-east-2.api.aws"),
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDNSView rejects a malformed globalResolverId by its modeled pattern, and
    separately rejects a well-formed but absent one by resource lookup, not the same way.
    """
    client = _client(ctx)

    malformed_id = "not an id !!!"
    code, message = _error(
        lambda: client.create_dns_view(globalResolverId=malformed_id, name="sim2real-view")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_pattern_message = (
        f"1 validation error detected: Value '{malformed_id}' at 'globalResolverId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [-.a-zA-Z0-9]+"
    )
    assert message == expected_pattern_message, f"unexpected message {message!r}"

    missing_id = ctx.unique_name("sim2real-behav-gr-")
    code, message = _error(
        lambda: client.create_dns_view(globalResolverId=missing_id, name="sim2real-view")
    )
    assert code == "ResourceNotFoundException", (
        f"a well-formed but absent globalResolverId must fail lookup, not shape, got "
        f"{code}: {message!r}"
    )
    expected_not_found_message = f"[{_NOT_FOUND_CODE}] No GlobalResolver found with the ID: {missing_id}"
    assert message == expected_not_found_message, f"unexpected message {message!r}"

    # Positive control: the client, credentials and us-east-2 control-plane endpoint actually
    # work, so the two rejections above are not an artifact of a universally broken call.
    listed = client.list_global_resolvers()
    assert "globalResolvers" in listed, f"ListGlobalResolvers response missing its key: {listed!r}"
    assert isinstance(listed["globalResolvers"], list), (
        f"globalResolvers must be a list, got {listed['globalResolvers']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
