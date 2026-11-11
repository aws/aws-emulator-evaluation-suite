"""oauth-connection-non-https-authorization-endpoint-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oauth-connection-non-https-authorization-endpoint-rejected"
GROUP = "connection"
SERVICES = ["events"]


def _oauth(endpoint: str) -> dict:
    return {"OAuthParameters": {
        "ClientParameters": {"ClientID": "sim2real-client", "ClientSecret": "sim2real-secret"},
        "AuthorizationEndpoint": endpoint,
        "HttpMethod": "POST",
    }}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnection refuses an OAuth connection with a plain-http AuthorizationEndpoint and
    creates nothing under that name, while the same request with an https endpoint is accepted
    and is the only connection listed under the prefix."""
    events = ctx.client("events")
    prefix = ctx.unique_name("sim2real-behav-conn-")

    insecure_name = f"{prefix}-http"
    insecure_url = "http://sim2real.invalid/oauth/token"
    ctx.on_cleanup(lambda: _delete_if_present(events, insecure_name))
    code, message = _error(lambda: events.create_connection(
        Name=insecure_name, AuthorizationType="OAUTH_CLIENT_CREDENTIALS", AuthParameters=_oauth(insecure_url)))
    expected = (
        "Failed to create the connection(s). Parameter AuthorizationEndpoint is not valid. Reason: "
        f"Endpoint '{insecure_url}' is invalid, please provide a valid HTTPS endpoint URL."
    )
    assert (code, message) == ("ValidationException", expected), (
        f"an http AuthorizationEndpoint must be refused, got {code!r} {message!r}"
    )
    gone = _error(lambda: events.describe_connection(Name=insecure_name))
    assert gone == (
        "ResourceNotFoundException",
        f"Failed to describe the connection(s). Connection '{insecure_name}' does not exist.",
    ), f"the refused connection must not exist; DescribeConnection gave {gone!r}"

    secure_name = f"{prefix}-https"
    created = events.create_connection(
        Name=secure_name, AuthorizationType="OAUTH_CLIENT_CREDENTIALS",
        AuthParameters=_oauth("https://sim2real.invalid/oauth/token"))
    ctx.on_cleanup(lambda: events.delete_connection(Name=secure_name))
    assert created["ConnectionArn"].split(":connection/")[1].split("/")[0] == secure_name, (
        "positive control: the https connection must be created under its own name"
    )

    listed = sorted(c["Name"] for c in events.list_connections(NamePrefix=prefix).get("Connections", []))
    assert listed == [secure_name], f"only the https connection may exist under the run prefix, got {listed!r}"


def _delete_if_present(events, name: str) -> None:
    """Teardown that deletes the refused connection only if it was wrongly created."""
    try:
        events.describe_connection(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    events.delete_connection(Name=name)


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
