"""op-contract-listOpenIDConnectProviders-membership."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listOpenIDConnectProviders-membership"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOpenIDConnectProviders includes a newly registered provider and omits it after
    deletion, when GetOpenIDConnectProvider fails with NoSuchEntity and its exact message."""
    iam = ctx.client("iam")
    host = ctx.unique_name("sim2real-batch09-oidc-").lower().replace("_", "-")
    url = f"https://{host}.example.com"
    thumbprint = "0" * 40  # a syntactically valid (but fake) SHA-1 thumbprint; supplying it skips IdP reachability

    arn = iam.create_open_id_connect_provider(
        Url=url, ThumbprintList=[thumbprint], ClientIDList=["sts.amazonaws.com"]
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: _delete_if_present(iam, arn))

    resp = iam.list_open_id_connect_providers()
    arns = {p["Arn"] for p in resp["OpenIDConnectProviderList"]}
    assert arn in arns, f"expected {arn} to be present in {arns}"

    # Error boundary: List takes no input to reject client-side, so the real negative is the
    # delete-then-list transition -- an independent read at the destination -- plus the
    # now-gone ARN's NoSuchEntity boundary on an independent Get.
    iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    after = {p["Arn"] for p in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]}
    assert arn not in after, f"expected {arn} removed from {after} after delete"

    code, message = _error(lambda: iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for deleted provider, got {code}"
    expected = f"OpenIDConnect Provider not found for arn {arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_if_present(iam, arn):
    try:
        iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
