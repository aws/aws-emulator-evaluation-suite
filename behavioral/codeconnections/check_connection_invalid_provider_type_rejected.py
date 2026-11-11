"""connection-invalid-provider-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-invalid-provider-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeconnections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection with a ProviderType outside the enum raises ValidationException and creates no
    connection, while ProviderType GitHub creates one."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]

    code, message = _error_code(
        lambda: cc.create_connection(ConnectionName=name, ProviderType="NotARealProvider")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value 'NotARealProvider' at 'providerType' failed to satisfy "
        "constraint: Member must be one of: [GitLab, GitHub, GitHubEnterpriseServer, AzureDevOps, "
        "GitLabSelfManaged, Bitbucket]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no connection with this name was created
    names = {c["ConnectionName"] for c in _iter_connections(cc)}
    assert name not in names, f"expected {name!r} absent from ListConnections, found it in {names!r}"

    # positive control: a valid provider type succeeds
    arn = cc.create_connection(
        ConnectionName=name,
        ProviderType="GitHub",
        Tags=[{"Key": "Owner", "Value": "sim2real"}],
    )["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))
    got = cc.get_connection(ConnectionArn=arn)["Connection"]
    assert got["ProviderType"] == "GitHub", f"expected ProviderType GitHub, got {got['ProviderType']!r}"


def _error_code(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _iter_connections(cc):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_connections(**kwargs)
        yield from resp.get("Connections", [])
        token = resp.get("NextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
