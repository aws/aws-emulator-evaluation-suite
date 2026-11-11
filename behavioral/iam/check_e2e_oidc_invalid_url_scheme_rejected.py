"""e2e-oidc-invalid-url-scheme-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-oidc-invalid-url-scheme-rejected"
GROUP = "e2e"
SERVICES = ["iam"]

_THUMBPRINT = "9e99a48a9960b14926bb7f3b02e22da2b0ab7280"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOpenIDConnectProvider rejects a Url that does not begin with
    https://, no provider is left behind at the ARN that would have been used,
    and creating the identical host with a proper https:// Url (positive
    control) succeeds and lands at exactly that ARN."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    host = f"{ctx.unique_name('sim2real-behav-oidc-neg-')}.example.com"
    invalid_url = f"http://{host}"  # must begin with https://, not http://
    valid_url = f"https://{host}"
    expected_arn = f"arn:aws:iam::{account_id}:oidc-provider/{host}"
    client_id = ctx.unique_name("sim2real-behav-aud-")

    # Break exactly one thing: the URL scheme.
    code, message = _error(
        lambda: iam.create_open_id_connect_provider(
            Url=invalid_url, ClientIDList=[client_id], ThumbprintList=[_THUMBPRINT]
        )
    )
    assert code == "InvalidInput", f"expected InvalidInput for non-https Url, got {code!r}"
    expected_message = None  # AWS sends this refusal with no Message element
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: nothing was created at the ARN this host would resolve to.
    absent_code, absent_message = _error(
        lambda: iam.get_open_id_connect_provider(OpenIDConnectProviderArn=expected_arn)
    )
    assert absent_code == "NoSuchEntity", (
        f"expected NoSuchEntity for {expected_arn}, got {absent_code!r}"
    )
    expected_absent = f"OpenIDConnect Provider not found for arn {expected_arn}"
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    # Positive control: the identical host, with the required https:// scheme,
    # succeeds and lands at exactly the ARN we probed above.
    provider_arn = iam.create_open_id_connect_provider(
        Url=valid_url,
        ClientIDList=[client_id],
        ThumbprintList=[_THUMBPRINT],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))

    assert provider_arn == expected_arn, f"expected ARN {expected_arn}, got {provider_arn}"
    got = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert got["ClientIDList"] == [client_id], (
        f"expected ClientIDList {[client_id]}, got {got['ClientIDList']}"
    )


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
