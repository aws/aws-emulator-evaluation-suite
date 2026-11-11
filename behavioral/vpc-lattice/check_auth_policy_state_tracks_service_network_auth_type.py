"""auth-policy-state-tracks-service-network-auth-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "auth-policy-state-tracks-service-network-auth-type"
GROUP = 'auth-policy-state'
SERVICES = ['vpc-lattice']


@tags("concern:representation", "axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """The same auth policy on a service network reports Active or Inactive purely from the
    network's current authType, and flips in both directions without re-putting the policy.
    """
    vl = ctx.client("vpc-lattice")
    kv = {"sim2real": "vpc-lattice-auth-policy-state"}

    net = vl.create_service_network(name=ctx.unique_name("sim2real-latt-aps-"), authType="NONE", tags=kv)
    ctx.on_cleanup(lambda i=net["id"]: vl.delete_service_network(serviceNetworkIdentifier=i))

    policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
        '"Action":"vpc-lattice-svcs:Invoke","Resource":"*"}]}'
    )
    put = vl.put_auth_policy(resourceIdentifier=net["id"], policy=policy)
    ctx.on_cleanup(lambda i=net["id"]: vl.delete_auth_policy(resourceIdentifier=i))
    assert put["state"] == "Inactive", (
        f"putting a policy on a NONE-auth network returned state {put['state']!r}, expected "
        f"'Inactive' since the network does not enforce AWS_IAM"
    )

    vl.update_service_network(serviceNetworkIdentifier=net["id"], authType="AWS_IAM")
    after_enable = vl.get_auth_policy(resourceIdentifier=net["id"])
    assert after_enable["state"] == "Active", (
        f"after switching the network to AWS_IAM, GetAuthPolicy reports {after_enable['state']!r} "
        f"for the SAME policy document, expected 'Active'"
    )
    assert after_enable["policy"] == policy, (
        f"the policy document changed to {after_enable['policy']!r} across an unrelated "
        f"UpdateServiceNetwork call; it must stay exactly what was put: {policy!r}"
    )

    vl.update_service_network(serviceNetworkIdentifier=net["id"], authType="NONE")
    after_disable = vl.get_auth_policy(resourceIdentifier=net["id"])
    assert after_disable["state"] == "Inactive", (
        f"after switching the network back to NONE, GetAuthPolicy reports "
        f"{after_disable['state']!r}, expected 'Inactive'"
    )
    assert after_disable["policy"] == policy, (
        f"the stored policy document must survive the round trip unchanged, got "
        f"{after_disable['policy']!r}"
    )

    vl.delete_auth_policy(resourceIdentifier=net["id"])
    cleared = vl.get_auth_policy(resourceIdentifier=net["id"])
    assert cleared.get("policy") is None, (
        f"after DeleteAuthPolicy, GetAuthPolicy still reports a policy: {cleared.get('policy')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
