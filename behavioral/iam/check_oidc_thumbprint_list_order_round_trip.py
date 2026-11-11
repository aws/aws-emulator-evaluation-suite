"""oidc-thumbprint-list-order-round-trip."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "oidc-thumbprint-list-order-round-trip"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The ThumbprintList array order supplied at creation, and after an
    UpdateOpenIDConnectProviderThumbprint call, is preserved exactly (not sorted or
    deduped) on subsequent GetOpenIDConnectProvider reads."""
    iam = ctx.client("iam")
    url = f"https://{ctx.unique_name('sim2real-oidctp-')}.example.com"

    t_f = "f" * 40
    t_1 = "1" * 40
    t_a = "a" * 40
    t_9 = "9" * 40

    # deliberately not in ascending lexical order ("1" < "a" < "f")
    initial = [t_f, t_1, t_a]
    resp = iam.create_open_id_connect_provider(
        Url=url,
        ThumbprintList=initial,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["OpenIDConnectProviderArn"]
    ctx.on_cleanup(
        lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    )

    fetched_initial = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)[
        "ThumbprintList"
    ]
    assert fetched_initial == initial, (
        f"expected order {initial}, got {fetched_initial}"
    )

    # deliberately not in ascending lexical order either ("9" < "a" < "f")
    updated_list = [t_a, t_9, t_f]
    iam.update_open_id_connect_provider_thumbprint(
        OpenIDConnectProviderArn=arn, ThumbprintList=updated_list
    )
    fetched_updated = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)[
        "ThumbprintList"
    ]
    assert fetched_updated == updated_list, (
        f"expected order {updated_list}, got {fetched_updated}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
