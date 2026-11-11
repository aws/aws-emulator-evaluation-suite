"""cluster-register-deregister-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-register-deregister-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _trust(service, extra_actions=()):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole", *extra_actions],
                }
            ],
        }
    )


def _ensure_role(ctx, name, service="eks.amazonaws.com", managed_policies=()):
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _wait_for(fn, pred, timeout_s=300, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _delete_role(iam, name):
    for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    iam.delete_role(RoleName=name)


_SSM_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


def _retry_on(fn, codes, timeout_s=420, interval_s=20):
    """Call fn, retrying while it fails with one of *codes* (genuinely-eventual EKS behavior)."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in codes or time.time() >= deadline:
                raise
            time.sleep(interval_s)


def _deregister_if_present(c, name):
    """Teardown: deregister the cluster unless the check already did."""
    try:
        c.deregister_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _gone(fn):
    """True once fn() answers ResourceNotFoundException, False while it succeeds (for gone-polling)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return True
    return False


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterCluster makes a connected cluster describable and listed only under include=all, a repeat
    register fails with ResourceInUseException, and after DeregisterCluster Describe and a repeat
    deregister fail with ResourceNotFoundException, all with exact messages.
    """
    c = ctx.client("eks")
    connector_role_name = ctx.unique_name(PREFIX + "eks-connector-")
    connector_role = _ensure_role(ctx, connector_role_name, "ssm.amazonaws.com", [_SSM_POLICY])
    ctx.on_cleanup(lambda: _delete_role(ctx.client("iam"), connector_role_name))
    name = ctx.unique_name("rc-")

    registered = _retry_on(
        lambda: c.register_cluster(
            name=name,
            connectorConfig={"roleArn": connector_role, "provider": "OTHER"},
            tags={"sim2real": "1"},
        ),
        # A brand-new connector IAM role reads as not-yet-usable until it propagates;
        # real EKS reports this as any of these codes.
        {
            "ResourcePropagationDelayException",
            "InvalidRequestException",
            "InvalidParameterException",
            "AccessDeniedException",
        },
        timeout_s=420, interval_s=20,
    )["cluster"]
    ctx.on_cleanup(lambda: _deregister_if_present(c, name))
    assert registered["name"] == name, registered
    assert registered["status"] in ("PENDING", "CREATING"), registered
    connector = registered["connectorConfig"]
    assert connector["activationId"], connector
    assert connector["activationCode"], connector
    assert connector["roleArn"] == connector_role, connector
    assert connector["provider"].upper() == "OTHER", connector

    described = c.describe_cluster(name=name)["cluster"]
    assert described["name"] == name, described
    assert described["connectorConfig"]["activationId"] == connector["activationId"], described
    # A connected cluster is NOT in the default ListClusters projection.
    default_projection = c.list_clusters()["clusters"]
    assert name not in default_projection, (
        f"connected cluster {name!r} must be absent from the default ListClusters "
        f"projection; got {default_projection!r}"
    )
    all_projection = c.list_clusters(include=["all"])["clusters"]
    assert name in all_projection, (
        f"connected cluster {name!r} must appear in ListClusters(include=['all']); "
        f"got {all_projection!r}"
    )

    reregister_code, reregister_message = _error(
        lambda: c.register_cluster(
            name=name, connectorConfig={"roleArn": connector_role, "provider": "OTHER"}
        )
    )
    assert reregister_code == "ResourceInUseException", (
        f"re-registering the in-use name {name!r} returned {reregister_code}, "
        f"expected ResourceInUseException"
    )
    assert reregister_message == f"Cluster already exists with name: {name}", reregister_message

    deregistered = c.deregister_cluster(name=name)["cluster"]
    assert deregistered["status"] == "DELETING", deregistered

    _wait_for(
        lambda: _gone(lambda: c.describe_cluster(name=name)),
        lambda gone: gone,
        timeout_s=300, interval_s=10, desc=f"cluster {name} gone",
    )
    not_found = f"No cluster found for name: {name}."
    describe_after_gone, describe_message = _error(lambda: c.describe_cluster(name=name))
    assert describe_after_gone == "ResourceNotFoundException", (
        f"describe_cluster({name!r}) after deregistration returned {describe_after_gone}, "
        f"expected ResourceNotFoundException"
    )
    assert describe_message == not_found, describe_message
    deregister_again, deregister_message = _error(lambda: c.deregister_cluster(name=name))
    assert deregister_again == "ResourceNotFoundException", (
        f"deregister_cluster({name!r}) on the already-gone cluster returned {deregister_again}, "
        f"expected ResourceNotFoundException"
    )
    assert deregister_message == not_found, deregister_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
