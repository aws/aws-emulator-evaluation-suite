"""certificate-authority-lifecycle-transitions."""
from __future__ import annotations

import json
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A successor CertificateAuthority moves NOT_USED -> (distribution COMPLETE) -> IN_USE
    on activation, the outgoing CA retires to NOT_USED, the retired CA can then be deleted,
    and Describe/List reflect a 404-equivalent (ResourceNotFoundException) after deletion."""
    eks = ctx.client("eks")

    # Each downstream poll below gets its own generous FIXED timeout rather than sharing a single
    # shrinking budget -- a merely slow-but-normal cluster-ACTIVE wait must not eat into the time
    # the later CA-rotation steps need.
    cluster_name = _create_active_cluster(ctx)

    initial = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(initial) == 1, f"expected exactly one CA on a fresh cluster, got {initial}"
    original_id = initial[0]["id"]
    assert initial[0]["signingStatus"] == "IN_USE", (
        f"expected the cluster's sole CA to be IN_USE, got {initial[0]['signingStatus']}"
    )

    created = eks.create_certificate_authority(clusterName=cluster_name)
    successor = created["certificateAuthority"]
    successor_id = successor["id"]
    assert successor["signingStatus"] == "NOT_USED", (
        f"expected a freshly created successor CA to be NOT_USED, got {successor['signingStatus']}"
    )
    assert successor_id != original_id, (
        f"CreateCertificateAuthority returned the same id as the original CA: {successor_id}"
    )

    listed = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    listed_ids = {ca["id"] for ca in listed}
    assert listed_ids == {original_id, successor_id}, (
        f"expected ListCertificateAuthorities to return {{{original_id}, {successor_id}}}, got {listed_ids}"
    )

    # CreateCertificateAuthority's own returned `update` (adding the CA to the cluster's trust
    # bundle) must reach a terminal state before the cluster's single update slot is free for the
    # next CA-mutating call -- confirmed on real AWS, which rejects a same-cluster CA update
    # attempted while another is still in progress with ResourceInUseException naming the
    # in-flight update id.
    create_update = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=created["update"]["id"])["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert create_update["status"] == "Successful", f"CA creation update did not succeed: {create_update}"

    # distributionStatus reaching COMPLETE is a real precondition for activation, not a
    # consequence of it -- confirmed on real AWS, which rejects an early
    # ActivateCertificateAuthority deterministically with InvalidRequestException ("cannot
    # activate CA: distributionStatus must be COMPLETE") rather than a transient
    # ResourceInUseException a bounded retry could ride out. Wait for the real precondition
    # instead of retrying past it.
    distributed = _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=successor_id
        )["certificateAuthority"],
        lambda ca: ca["distributionStatus"] == "COMPLETE",
        timeout_s=2400.0,
        interval_s=20.0,
    )
    assert distributed["distributionStatus"] == "COMPLETE", (
        f"successor CA distribution did not reach COMPLETE before activation, got {distributed}"
    )

    activated = eks.activate_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=successor_id
    )
    update_id = activated["update"]["id"]
    assert update_id, "ActivateCertificateAuthority must return an async update id"
    activated_status = activated["certificateAuthority"]["signingStatus"]
    assert activated_status in ("ACTIVATING", "IN_USE"), (
        f"expected the successor's signingStatus right after activation to be ACTIVATING or IN_USE, "
        f"got {activated_status}"
    )

    # ActivateCertificateAuthority is documented as an asynchronous operation tracked via
    # DescribeUpdate -- polling the update's own status is the authoritative signal that BOTH
    # halves of the rotation (successor -> IN_USE + distribution COMPLETE, outgoing -> NOT_USED)
    # have landed, rather than guessing at completion by separately re-polling
    # describe_certificate_authority for each CA in sequence (which only adds an extra,
    # independently-timed wait window on top of the update's own settle time). Include the
    # FAILED/Cancelled terminal states alongside Successful: without them, a genuinely failed
    # update would never satisfy the predicate and this poll would spin for its entire timeout_s
    # instead of surfacing the failure quickly.
    finished_update = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=900.0,
        interval_s=5.0,
    )
    assert finished_update["status"] == "Successful", f"CA activation update did not succeed: {finished_update}"

    successor_final = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert successor_final["signingStatus"] == "IN_USE", (
        f"expected the activated successor's signingStatus to settle at IN_USE, got {successor_final['signingStatus']}"
    )
    assert successor_final["distributionStatus"] == "COMPLETE", (
        f"successor CA distribution did not complete after activation: {successor_final}"
    )

    original_final = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=original_id
    )["certificateAuthority"]
    assert original_final["signingStatus"] == "NOT_USED", (
        f"expected the outgoing CA to retire to NOT_USED after the successor activated, "
        f"got {original_final['signingStatus']}"
    )

    # Negative: the CA that is currently signing (successor, now IN_USE) cannot be deleted.
    in_use_delete_code, in_use_delete_msg = _error(
        lambda: eks.delete_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=successor_id
        )
    )
    assert in_use_delete_code == "ResourceInUseException", (
        f"expected DeleteCertificateAuthority on the IN_USE signer to be rejected with "
        f"ResourceInUseException, got {in_use_delete_code!r}"
    )
    expected = "Cannot delete the active certificate authority. Activate a different CA first."
    assert in_use_delete_msg == expected, f"expected message {expected!r}, got {in_use_delete_msg!r}"
    still_present = eks.describe_certificate_authority(
        clusterName=cluster_name, certificateAuthorityId=successor_id
    )["certificateAuthority"]
    assert still_present["signingStatus"] == "IN_USE", (
        f"the rejected delete must leave the signer's signingStatus unchanged at IN_USE, "
        f"got {still_present['signingStatus']}"
    )

    # Positive: the now-retired original CA (NOT_USED) can be deleted.
    delete_resp = eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=original_id)
    delete_update_id = delete_resp["update"]["id"]
    # Wait for the delete's own update to reach a terminal state before treating the cluster's
    # single update slot as free (same real constraint as create/activate above) -- confirmed on
    # real AWS, which rejected an immediate repeat DeleteCertificateAuthority on this same id with
    # ResourceInUseException even after DescribeCertificateAuthority already 404'd it: the resource
    # disappearing from reads and the cluster's update slot releasing are two independently-timed
    # signals, and the mutation beat below needs the second one.
    finished_delete_update = _poll_until(
        lambda: eks.describe_update(name=cluster_name, updateId=delete_update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert finished_delete_update["status"] == "Successful", f"CA deletion update did not succeed: {finished_delete_update}"

    _wait_deleted(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=original_id
        ),
        timeout_s=600.0,
        interval_s=10.0,
    )

    not_found_code, not_found_msg = _error(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=original_id
        )
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected DescribeCertificateAuthority on the deleted CA to 404 with "
        f"ResourceNotFoundException, got {not_found_code!r}"
    )
    # The message embeds a backend request id the check never sees; its fixed text is asserted.
    assert not_found_msg.startswith(
        "certificate authority not found (Service: EksCertificateAuthority, Status Code: 404, Request ID: "
    ) and not_found_msg.endswith(") (SDK Attempt Count: 1)"), not_found_msg

    # A mutation on the now-dead id must fail the same way as the read: the deletion
    # is not just invisible to a read, it also makes the id unusable for further calls. By this
    # point the delete's own update has already reached a terminal state above, so the cluster's
    # update slot is free and this can no longer collide with it.
    redelete_code, redelete_msg = _error(
        lambda: eks.delete_certificate_authority(
            clusterName=cluster_name, certificateAuthorityId=original_id
        )
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second DeleteCertificateAuthority on the already-deleted CA to also 404 with "
        f"ResourceNotFoundException, got {redelete_code!r}"
    )
    expected = f"Certificate authority {original_id} not found for cluster {cluster_name}"
    assert redelete_msg == expected, f"expected message {expected!r}, got {redelete_msg!r}"

    remaining = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    remaining_ids = {ca["id"] for ca in remaining}
    assert original_id not in remaining_ids, (
        f"deleted CA {original_id} must not still appear in ListCertificateAuthorities: {remaining_ids}"
    )
    assert successor_id in remaining_ids, (
        f"the still-IN_USE successor {successor_id} must remain in ListCertificateAuthorities: {remaining_ids}"
    )


# ===== helpers =====


def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _poll_until(probe, predicate, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _wait_deleted(describe_fn, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe_fn()
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"resource still present after {timeout_s}s")


def _retry_delete(fn, attempts=20, delay_s=15):
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if "NotFound" in code:
                return
            if i == attempts - 1:
                raise
            time.sleep(delay_s)


def _create_vpc_infra(ctx):
    ec2 = ctx.client("ec2")
    # Reuse the run's shared network (already has an Internet Gateway + public,
    # map-public-ip-on-launch subnets across AZs) instead of provisioning a brand-new
    # VPC/IGW/route-table/subnets per check. This shaves the several sequential EC2 provisioning
    # calls (and their latency) off the front of a check whose remaining budget, after the
    # cluster reaches ACTIVE and the certificate-authority rotation runs its course, is already
    # tight against the harness's per-check timeout -- and avoids contributing to the per-region
    # Internet Gateway quota that other checks in this batch can exhaust.
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        default_subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        )["Subnets"]
        by_az: dict[str, str] = {}
        for s in default_subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return [sid for _, sid in sorted(by_az.items())][:2]

    # Fallback (no usable shared network in this account/region): provision a dedicated one.
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [a["ZoneName"] for a in azs[:2]]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-igw-")}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _teardown_igw():
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        _retry_delete(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))

    ctx.on_cleanup(_teardown_igw)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-rt-")}]}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.77.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-subnet{i}-")}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role(ctx, trust_principal, actions, managed_policies=()):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": actions}],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policies:
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        _retry_delete(lambda: iam.delete_role(RoleName=name), attempts=5, delay_s=5)

    ctx.on_cleanup(_cleanup)
    return arn


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    # Fetch the reusable default-VPC subnets and create the cluster IAM role CONCURRENTLY
    # (independent work, both fast on their own, but every second shaved off the front of this
    # check matters: the CA rotation state machine below still has to chain a distribution wait
    # and an activation-update wait inside the same fixed per-check budget after cluster ACTIVE).
    _prep: dict = {}

    def _prep_vpc():
        _prep["subnet_ids"] = _create_vpc_infra(ctx)

    def _prep_role():
        _prep["role_arn"] = _create_role(
            ctx, "eks.amazonaws.com", "sts:AssumeRole",
            managed_policies=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
        )

    vpc_thread = threading.Thread(target=_prep_vpc)
    vpc_thread.start()
    _prep_role()
    vpc_thread.join()
    subnet_ids = _prep["subnet_ids"]
    role_arn = _prep["role_arn"]
    cluster_name = ctx.unique_name("sim2real-eks-cluster-")

    def _create():
        # This check never schedules a Pod (no nodegroup/Fargate profile/EKS Auto Mode instance
        # is ever created), so the default networking add-ons (vpc-cni/coredns/kube-proxy) this
        # cluster would otherwise auto-install are pure unneeded async setup work for a
        # certificate-authority-only test -- skip them to keep the cluster-creation wait (which
        # this check, unlike its siblings, must complete before it can even start exercising the
        # CA rotation state machine) as small as possible against the harness's per-check
        # timeout.
        return eks.create_cluster(
            name=cluster_name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids, "endpointPublicAccess": True, "endpointPrivateAccess": False},
            bootstrapSelfManagedAddons=False,
        )

    # A freshly-created IAM role isn't always immediately assumable (propagation lag). Rather
    # than unconditionally sleeping before the first attempt (which costs the same fixed delay on
    # every run, even the common case where the role is already assumable), rely solely on the
    # reactive retry-on-error loop below -- it only pays the delay when propagation lag actually
    # manifests as a CreateCluster failure, saving that time on every check on real AWS.
    last_err = None
    for _ in range(10):
        try:
            _create()
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("ClientException", "InvalidParameterException"):
                time.sleep(3)
                continue
            raise
    else:
        raise last_err

    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(eks, cluster_name))

    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] == "ACTIVE",
        timeout_s=1200.0,
        interval_s=15.0,
    )
    return cluster_name


# EC2 network teardown: a cluster in this VPC deletes asynchronously and its ENIs keep DeleteSubnet /
# DeleteVpc failing with DependencyViolation for minutes, so wait for the ENIs, retry that code to one
# deadline shared by the check's network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
