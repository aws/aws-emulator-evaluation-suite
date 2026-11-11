"""create-app-monitor-malformed-domain-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-app-monitor-malformed-domain-rejected"
GROUP = "overly-permissive"
SERVICES = ["rum"]

_DOMAIN_PATTERN_MESSAGE = (
    "1 validation error detected: Value 'http://example.com' at 'domain' failed to satisfy "
    "constraint: Member must satisfy regular expression pattern: "
    r"(localhost)$|^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    r"|(?=^[a-zA-Z0-9\.\*-]{4,253}$)(?!.*\.-)(?!.*-\.)(?!.*\.\.)(?!.*[^\.]{64,})^(\*\.)?"
    r"(?![-\.\*])[^\*]{1,}\.(\*|(?!.*--)(?=.*[a-zA-Z])[^\*]{1,}[^\*-])"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAppMonitor with a syntactically invalid Domain (protocol prefix + slashes,
    which the documented Domain pattern forbids) is rejected with ValidationException,
    and no app monitor is left behind under that name."""
    rum = ctx.client("rum")
    bad_name = ctx.unique_name("sim2real-rum-baddomain-")

    code, message = _client_error(lambda: rum.create_app_monitor(Name=bad_name, Domain="http://example.com"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == _DOMAIN_PATTERN_MESSAGE, (
        f"expected message {_DOMAIN_PATTERN_MESSAGE!r}, got {message!r}"
    )

    # effect absent: the rejected create must not have left an app monitor behind
    get_code, get_message = _client_error(lambda: rum.get_app_monitor(Name=bad_name))
    assert get_code == "ResourceNotFoundException", (
        f"malformed-domain create should not have created {bad_name!r}, got {get_code!r}"
    )
    expected_get = f"Resource not found {bad_name}"
    assert get_message == expected_get, f"expected message {expected_get!r}, got {get_message!r}"

    # positive control: a syntactically valid domain succeeds in the same file
    good_name = ctx.unique_name("sim2real-rum-gooddomain-")
    rum.create_app_monitor(Name=good_name, Domain="example.com", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=good_name))
    resp = rum.get_app_monitor(Name=good_name)
    assert resp["AppMonitor"]["Domain"] == "example.com", (
        f"expected positive control domain 'example.com', got {resp['AppMonitor'].get('Domain')!r}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
