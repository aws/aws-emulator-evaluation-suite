"""create-host-provider-endpoint-exceeding-max-length-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-host-provider-endpoint-exceeding-max-length-rejected"
GROUP = "overly-permissive"
SERVICES = ["codeconnections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHost rejects a ProviderEndpoint longer than the documented 512-character
    maximum with ValidationException, and no host is created; a short, valid endpoint
    still succeeds (positive control)."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-host-")[:64]
    too_long_endpoint = "https://" + ("a" * 600) + ".example.com"
    assert len(too_long_endpoint) > 512, (
        f"test setup: constructed endpoint is {len(too_long_endpoint)} chars, expected > 512"
    )

    code, message = _error_code(
        lambda: cc.create_host(
            Name=name,
            ProviderType="GitHubEnterpriseServer",
            ProviderEndpoint=too_long_endpoint,
        )
    )
    assert code == "ValidationException", (
        f"a ProviderEndpoint over 512 characters should be rejected with "
        f"ValidationException, got {code!r}"
    )
    expected = (
        "1 validation error detected: Value at 'providerEndpoint' failed to satisfy constraint: "
        "Member must have length less than or equal to 512"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no host with this name was created
    names = {h["Name"] for h in _iter_hosts(cc)}
    assert name not in names, (
        f"CreateHost with an over-length ProviderEndpoint was rejected, but a host "
        f"named {name!r} exists anyway"
    )

    # positive control: a short, valid endpoint succeeds
    arn = cc.create_host(
        Name=name,
        ProviderType="GitHubEnterpriseServer",
        ProviderEndpoint="https://ghe.example.com",
    )["HostArn"]
    ctx.on_cleanup(lambda: cc.delete_host(HostArn=arn))
    got_name = cc.get_host(HostArn=arn)["Name"]
    assert got_name == name, (
        f"positive control: expected the created host's Name to be {name!r}, got "
        f"{got_name!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _iter_hosts(cc):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cc.list_hosts(**kwargs)
        yield from resp.get("Hosts", [])
        token = resp.get("NextToken")
        if not token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
