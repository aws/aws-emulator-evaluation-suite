"""describe-connection-redacts-secret-auth-material."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

# The labels H1-H6 in assertion messages name the claims: H1 no secret is returned (the response
# shapes carry only ApiKeyName/Username), H2 identifiers are returned, H4 API_KEY authorizes with no
# egress, H5 SecretArn is in the caller's account and region, H6 the OAuth leg leaves CREATING.
# The value of an IsValueSecret=False parameter is deliberately not asserted: the docs do not say.

CHECK = "describe-connection-redacts-secret-auth-material"
GROUP = "connection"
SERVICES = ["events"]

_AUTHORIZED_TIMEOUT_S = 120.0
_TERMINAL_TIMEOUT_S = 120.0
# RFC 5737 TEST-NET-1: reserved for documentation, routed nowhere. Used so the OAuth token fetch
# cannot reach anything real — this check must not depend on an external endpoint.
_UNROUTABLE_OAUTH_ENDPOINT = "https://192.0.2.1/oauth2/token"


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DescribeConnection and ListConnections return every API_KEY/BASIC/OAuth identifier and
    none of the secrets (API key value, password, client secret, secret header value).
    """
    events = ctx.client("events")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Per-run uuid4 values: a secret hit cannot be coincidence, and identifiers are a real control.
    ids = {k: uuid.uuid4().hex for k in ("apikeyname", "username", "clientid", "hdrkey", "qskey")}
    secrets = {k: uuid.uuid4().hex for k in ("apikeyvalue", "password", "clientsecret", "hdrsecret")}
    plain_qs_value = uuid.uuid4().hex

    invocation_http = {
        "HeaderParameters": [
            {"Key": f"x-sim2real-{ids['hdrkey']}", "Value": secrets["hdrsecret"], "IsValueSecret": True},
        ],
        "QueryStringParameters": [
            {"Key": f"q{ids['qskey']}", "Value": plain_qs_value, "IsValueSecret": False},
        ],
    }

    # API_KEY is the only authorization type that needs no network egress to authorize.
    api_key_conn = _create_connection(
        ctx,
        "API_KEY",
        {
            "ApiKeyAuthParameters": {
                "ApiKeyName": f"x-api-key-{ids['apikeyname']}",
                "ApiKeyValue": secrets["apikeyvalue"],
            },
            "InvocationHttpParameters": invocation_http,
        },
    )
    authorized = _poll_until(
        lambda: events.describe_connection(Name=api_key_conn),
        lambda d: d["ConnectionState"] in ("AUTHORIZED", "CREATE_FAILED"),
        timeout_s=_AUTHORIZED_TIMEOUT_S,
        interval_s=2.0,
        description=f"API_KEY connection {api_key_conn} leaves CREATING (H4)",
    )
    assert authorized["ConnectionState"] == "AUTHORIZED", (
        f"an API_KEY connection authorizes with no upstream call; expected "
        f"ConnectionState=AUTHORIZED, got {authorized['ConnectionState']!r} "
        f"StateReason={authorized.get('StateReason')!r}"
    )
    secret_arn = authorized.get("SecretArn")
    expected_fragment = f":secretsmanager:{ctx.region}:{account}:secret:"
    assert secret_arn and expected_fragment in secret_arn, (
        f"the connection must store its credential in a Secrets Manager secret in this account and "
        f"region: expected an ARN containing {expected_fragment!r}, got SecretArn={secret_arn!r} (H5)"
    )
    _assert_identifiers_present(
        authorized,
        must_contain=[
            f"x-api-key-{ids['apikeyname']}",
            f"x-sim2real-{ids['hdrkey']}",
            f"q{ids['qskey']}",
        ],
        label=f"DescribeConnection({api_key_conn})",
    )
    _assert_no_secrets(authorized, secrets, label=f"DescribeConnection({api_key_conn})")
    api_key_params = authorized.get("AuthParameters") or {}
    assert (api_key_params.get("ApiKeyAuthParameters") or {}).get("ApiKeyName") == (
        f"x-api-key-{ids['apikeyname']}"
    ), (
        f"ApiKeyAuthParameters.ApiKeyName must round-trip exactly; expected "
        f"'x-api-key-{ids['apikeyname']}', got {api_key_params.get('ApiKeyAuthParameters')!r}"
    )
    assert "ApiKeyValue" not in json.dumps(api_key_params), (
        f"the response must not even carry an ApiKeyValue member, got {api_key_params!r}"
    )
    header_params = (
        (api_key_params.get("InvocationHttpParameters") or {}).get("HeaderParameters") or []
    )
    assert len(header_params) == 1, (
        f"exactly the one header parameter that was set must come back, got {header_params!r}"
    )
    assert header_params[0].get("IsValueSecret") is True, (
        f"IsValueSecret must round-trip as True for the secret header, got {header_params[0]!r}"
    )

    basic_conn = _create_connection(
        ctx,
        "BASIC",
        {
            "BasicAuthParameters": {
                "Username": f"u-{ids['username']}",
                "Password": secrets["password"],
            }
        },
    )
    basic = _poll_until(
        lambda: events.describe_connection(Name=basic_conn),
        lambda d: d["ConnectionState"] != "CREATING",
        timeout_s=_TERMINAL_TIMEOUT_S,
        interval_s=2.0,
        description=f"BASIC connection {basic_conn} leaves CREATING",
    )
    _assert_identifiers_present(
        basic, must_contain=[f"u-{ids['username']}"], label=f"DescribeConnection({basic_conn})"
    )
    _assert_no_secrets(basic, secrets, label=f"DescribeConnection({basic_conn})")
    assert "Password" not in json.dumps(basic.get("AuthParameters") or {}), (
        f"the response must not carry a Password member at all, got {basic.get('AuthParameters')!r}"
    )

    oauth_conn = _create_connection(
        ctx,
        "OAUTH_CLIENT_CREDENTIALS",
        {
            "OAuthParameters": {
                "ClientParameters": {
                    "ClientID": f"c-{ids['clientid']}",
                    "ClientSecret": secrets["clientsecret"],
                },
                "AuthorizationEndpoint": _UNROUTABLE_OAUTH_ENDPOINT,
                "HttpMethod": "POST",
            }
        },
    )
    oauth = _poll_until(
        lambda: events.describe_connection(Name=oauth_conn),
        lambda d: d["ConnectionState"] != "CREATING",
        timeout_s=_TERMINAL_TIMEOUT_S,
        interval_s=3.0,
        description=f"OAUTH connection {oauth_conn} leaves CREATING (H6)",
    )
    _assert_identifiers_present(
        oauth,
        must_contain=[f"c-{ids['clientid']}", _UNROUTABLE_OAUTH_ENDPOINT],
        label=f"DescribeConnection({oauth_conn})",
    )
    _assert_no_secrets(oauth, secrets, label=f"DescribeConnection({oauth_conn})")
    assert "ClientSecret" not in json.dumps(oauth.get("AuthParameters") or {}), (
        f"the response must not carry a ClientSecret member at all, got "
        f"{oauth.get('AuthParameters')!r}"
    )

    # The list surface must not leak either.
    for name in (api_key_conn, basic_conn, oauth_conn):
        page = events.list_connections(NamePrefix=name)
        names = [c["Name"] for c in page.get("Connections", [])]
        assert names == [name], (
            f"ListConnections(NamePrefix={name!r}) must return exactly that connection, got {names}"
        )
        _assert_no_secrets(page, secrets, label=f"ListConnections({name})")


_PREFIX = "sim2real-behav-"


def _create_connection(ctx, authorization_type: str, auth_parameters: dict) -> str:
    """Create a connection, register its teardown, and return its name."""
    events = ctx.client("events")
    name = ctx.unique_name(f"{_PREFIX}conn-")
    events.create_connection(
        Name=name,
        Description="sim2real describe-connection-redacts-secret-auth-material",
        AuthorizationType=authorization_type,
        AuthParameters=auth_parameters,
    )
    ctx.on_cleanup(lambda n=name: _delete_connection_quietly(ctx, n))
    return name


def _delete_connection_quietly(ctx, name: str) -> None:
    """Delete a connection, tolerating one already gone."""
    try:
        ctx.client("events").delete_connection(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise RuntimeError(f"could not delete connection {name}: {exc}") from exc


def _assert_no_secrets(payload, secrets: dict[str, str], *, label: str) -> None:
    """No secret nonce may appear ANYWHERE in the serialised response."""
    blob = json.dumps(payload, default=str)
    leaked = sorted(k for k, v in secrets.items() if v in blob)
    assert leaked == [], (
        f"{label} leaked secret material {leaked} — a read-only EventBridge API returned the "
        f"credential half of the connection's AuthParameters (H1). Response was {blob[:400]}"
    )


def _assert_identifiers_present(payload, *, must_contain: list[str], label: str) -> None:
    """Positive control: the response really is about THIS connection and carries its identifiers."""
    blob = json.dumps(payload, default=str)
    missing = [needle for needle in must_contain if needle not in blob]
    assert missing == [], (
        f"{label} did not return the non-secret identifiers {missing} — without them the redaction "
        f"assertions would also pass against a target that returns an empty AuthParameters (H2). "
        f"Response was {blob[:400]}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll until predicate holds; RAISE on timeout (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
