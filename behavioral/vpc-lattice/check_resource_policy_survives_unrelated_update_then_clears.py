"""resource-policy-survives-unrelated-update-then-clears."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-survives-unrelated-update-then-clears"
GROUP = 'resource-policy-persistence'
SERVICES = ['vpc-lattice']


def _error(fn):
    """The AWS (code, message) ``fn()`` raised; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("concern:representation", "axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A resource policy survives an unrelated UpdateServiceNetwork call untouched, and clearing
    it leaves the service network itself fully intact.
    """
    vl = ctx.client("vpc-lattice")
    kv = {"sim2real": "vpc-lattice-resource-policy-persistence"}

    net = vl.create_service_network(name=ctx.unique_name("sim2real-latt-rpp-"), authType="NONE", tags=kv)
    ctx.on_cleanup(lambda i=net["id"]: vl.delete_service_network(serviceNetworkIdentifier=i))

    policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"arn:aws:iam::{ctx.account}:root"}},'
        '"Action":"vpc-lattice:CreateServiceNetworkVpcAssociation",'
        f'"Resource":"{net["arn"]}"}}]}}'
    )
    vl.put_resource_policy(resourceArn=net["arn"], policy=policy)
    ctx.on_cleanup(lambda a=net["arn"]: vl.delete_resource_policy(resourceArn=a))

    read_back = vl.get_resource_policy(resourceArn=net["arn"])
    assert read_back["policy"] == policy, (
        f"GetResourcePolicy returned {read_back['policy']!r} right after Put, expected {policy!r}"
    )

    # An unrelated mutation of the resource the policy is attached to must not touch the policy.
    vl.update_service_network(serviceNetworkIdentifier=net["id"], authType="AWS_IAM")
    unaffected = vl.get_resource_policy(resourceArn=net["arn"])
    assert unaffected["policy"] == policy, (
        f"after UpdateServiceNetwork changed authType, the resource policy reads back as "
        f"{unaffected['policy']!r}; it must still be exactly {policy!r}"
    )

    still_there = vl.get_service_network(serviceNetworkIdentifier=net["id"])
    assert still_there["authType"] == "AWS_IAM", (
        f"the service network's own authType is {still_there['authType']!r} after the update, "
        f"expected 'AWS_IAM' -- the resource policy check above must not be masking a failed update"
    )

    vl.delete_resource_policy(resourceArn=net["arn"])
    cleared = vl.get_resource_policy(resourceArn=net["arn"])
    assert cleared.get("policy") is None, (
        f"after DeleteResourcePolicy, GetResourcePolicy still reports {cleared.get('policy')!r}"
    )

    # The resource itself must be wholly unaffected by having carried, then lost, a policy.
    final = vl.get_service_network(serviceNetworkIdentifier=net["id"])
    assert final["authType"] == "AWS_IAM" and final["name"] == net["name"], (
        f"the service network changed after its resource policy was deleted: {final!r}"
    )

    error = _error(lambda: vl.get_resource_policy(resourceArn=net["id"]))
    expected_message = (
        f"1 validation error detected: Value '{net['id']}' at 'resourceArn' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: "
        f"arn(:[a-z0-9]+([.-][a-z0-9]+)*){{2}}(:([a-z0-9]+([.-][a-z0-9]+)*)?){{2}}:"
        f"((servicenetwork/sn)|(service/svc)|(resourceconfiguration/rcfg))-[0-9a-z]{{17}}"
    )
    assert error == ("ValidationException", expected_message), (
        f"reading a resource policy by the bare id {net['id']!r} (not a full ARN) raised "
        f"{error!r}, expected ('ValidationException', {expected_message!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
