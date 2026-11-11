"""register-cluster-client-request-token-is-idempotent."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-cluster-client-request-token-is-idempotent"
GROUP = 'state'
SERVICES = ['eks']


# RegisterCluster is used because it is the only EKS operation that mints a real
# cluster resource with a clientRequestToken for free: no control plane, no EC2.


def _error_code(fn):
    """Call fn; return the botocore error Code, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {desc}; last={val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get(
            "AttachedPolicies", []
        ):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_connector_role(ctx):
    """Create an IAM role the EKS connector service can assume; return its ARN."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-connector-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["eks-connector.amazonaws.com", "ssm.amazonaws.com"]
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="candidates_09 eks fidelity check: EKS connector role",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonEKSConnectorAgentPolicy",
        )
    except ClientError:
        pass
    return f"arn:aws:iam::{account}:role/{role_name}"


def _expect_error(fn):
    """Require fn() to raise; return (Code, Message). Fails loudly if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("call unexpectedly succeeded")


def _names_in_list_clusters(c, name) -> int:
    """How many times *name* appears in a full paginated ListClusters walk.

    include=['all'] is mandatory: ListClusters returns only Amazon EKS clusters by
    default, so a CONNECTED cluster is invisible without it.
    """
    count = 0
    token = None
    pages = 0
    while True:
        kwargs = {"maxResults": 100, "include": ["all"]}
        if token:
            kwargs["nextToken"] = token
        resp = c.list_clusters(**kwargs)
        count += sum(1 for n in resp.get("clusters", []) if n == name)
        token = resp.get("nextToken")
        pages += 1
        if not token:
            return count
        assert pages <= 200, "ListClusters pagination did not terminate"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterCluster's clientRequestToken is no idempotency key: for a registered name, the same token and
    body, another token or none are each refused with the same ResourceInUseException naming it and the name
    stays listed once, while the same token under a new name registers a cluster with a new ARN."""
    c = ctx.client("eks")
    role_arn = _create_connector_role(ctx)
    name = ctx.unique_name("sim2real-behav-connected-")
    token = str(uuid.uuid4())
    body = {
        "name": name,
        "connectorConfig": {"roleArn": role_arn, "provider": "OTHER"},
        "clientRequestToken": token,
        "tags": {"sim2real": "1"},
    }
    ctx.on_cleanup(lambda: c.deregister_cluster(name=name))

    def attempt():
        try:
            return c.register_cluster(**body)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in (
                "ResourcePropagationDelayException",
                "InvalidRequestException",
                "InvalidParameterException",
                "AccessDeniedException",
            ):
                return None
            raise

    # EKS validates the connector role synchronously; a brand-new role reads as
    # nonexistent until IAM propagates. No fixed sleep -- the retry loop below
    # bounds the wait on the connector role actually becoming usable.
    first = _wait_for(
        attempt,
        lambda r: r is not None,
        timeout_s=240,
        interval_s=5,
        desc="RegisterCluster accepted (connector role propagation)",
    )["cluster"]
    assert first["name"] == name, first
    assert first.get("arn"), f"RegisterCluster returned no arn: {first!r}"

    # (1) Same token, byte-identical body: REFUSED, not replayed. No retry wrapper -- the role
    #     is already propagated, so any error is real signal.
    replay_code, replay_msg = _expect_error(lambda: c.register_cluster(**body))
    assert replay_code == "ResourceInUseException", (
        f"replaying RegisterCluster with the SAME clientRequestToken {token!r} and an identical "
        f"body returned {replay_code}: {replay_msg}. Real AWS refuses it with "
        f"ResourceInUseException -- the token is not a replay-dedup key, so returning the first "
        f"cluster here would be an invented idempotency guarantee"
    )
    assert name in replay_msg, (
        f"the conflict must name the cluster that already exists; got {replay_msg!r}"
    )

    # (2) A DIFFERENT token for the same name is refused identically -- same code, same message.
    #     Without this, (1) would also pass on an emulator that keys the conflict on the TOKEN.
    other_code, other_msg = _expect_error(
        lambda: c.register_cluster(
            name=name,
            connectorConfig={"roleArn": role_arn, "provider": "OTHER"},
            clientRequestToken=str(uuid.uuid4()),
        )
    )
    assert other_code == "ResourceInUseException", (
        f"a fresh clientRequestToken for the existing name {name!r} returned {other_code}, "
        f"expected ResourceInUseException"
    )
    assert other_msg == replay_msg, (
        f"the token must make no difference to the conflict: same-token replay said "
        f"{replay_msg!r}, different-token said {other_msg!r}"
    )

    # (3) And OMITTING the token entirely is refused the same way, which is the sharpest
    #     statement that the token is not part of the conflict key.
    absent_code, absent_msg = _expect_error(
        lambda: c.register_cluster(
            name=name, connectorConfig={"roleArn": role_arn, "provider": "OTHER"}
        )
    )
    assert absent_code == "ResourceInUseException", (
        f"omitting clientRequestToken for the existing name {name!r} returned {absent_code}, "
        f"expected ResourceInUseException"
    )
    assert absent_msg == replay_msg, (absent_msg, replay_msg)

    # (4) Effect: exactly one cluster carries the name -- none of the three refusals duplicated
    #     it, and none of them was silently accepted.
    seen = _names_in_list_clusters(c, name)
    assert seen == 1, (
        f"ListClusters reports {name!r} {seen} times after three refused RegisterCluster calls; "
        f"expected exactly 1"
    )

    # (5) Converse: the SAME token under a DIFFERENT name mints a SECOND, distinct cluster. An
    #     emulator that dedupes on the token returns the first cluster's ARN here.
    second_name = ctx.unique_name("sim2real-behav-connected-")
    ctx.on_cleanup(lambda: c.deregister_cluster(name=second_name))
    second = c.register_cluster(
        name=second_name,
        connectorConfig={"roleArn": role_arn, "provider": "OTHER"},
        clientRequestToken=token,
        tags={"sim2real": "1"},
    )["cluster"]
    assert second["name"] == second_name, second
    assert second["arn"] != first["arn"], (
        f"reusing clientRequestToken {token!r} under a new name returned the FIRST cluster's arn "
        f"{first['arn']!r}; real AWS mints a distinct cluster because the token is not a dedup key"
    )
    assert _names_in_list_clusters(c, second_name) == 1, (
        f"ListClusters does not report exactly one {second_name!r}"
    )

    # (6) Control: the original cluster is intact and unchanged after all of it.
    after = c.describe_cluster(name=name)["cluster"]
    assert after["arn"] == first["arn"], (after["arn"], first["arn"])
    assert after.get("connectorConfig"), (
        f"connectorConfig disappeared from {name!r} after the refusals: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
