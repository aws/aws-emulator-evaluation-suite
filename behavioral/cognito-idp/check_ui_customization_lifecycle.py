"""ui-customization-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "ui-customization-lifecycle"
GROUP = 'state-machine'
SERVICES = ['cognito-idp']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUICustomization for a specific client is retrievable via
    GetUICustomization and updates in place. Requires a domain associated
    with the pool (doesn't need to be ACTIVE for this API)."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    domain = ctx.unique_name("sim2real-behav-cip-domain-").lower()
    c.create_user_pool_domain(Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=1)
    ctx.on_cleanup(lambda _p=pool_id, _d=domain: c.delete_user_pool_domain(Domain=_d, UserPoolId=_p))

    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    css1 = ".label-customizable {font-weight: 400;}"
    c.set_ui_customization(UserPoolId=pool_id, ClientId=client_id, CSS=css1)
    got1 = c.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
    assert got1["CSS"] == css1, got1.get("CSS")

    css2 = ".label-customizable {font-weight: 700;}"
    c.set_ui_customization(UserPoolId=pool_id, ClientId=client_id, CSS=css2)
    got2 = c.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
    assert got2["CSS"] == css2, got2.get("CSS")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
