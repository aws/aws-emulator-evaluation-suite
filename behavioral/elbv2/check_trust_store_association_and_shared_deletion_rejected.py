"""trust-store-association-and-shared-deletion-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "trust-store-association-and-shared-deletion-rejected"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A listener's mutual-TLS trust store is listed by DescribeTrustStoreAssociations under the load balancer ARN;
    DeleteSharedTrustStoreAssociation on it fails with DeleteAssociationSameAccount and the exact message and keeps
    the association, which detaching the trust store removes."""

    _net_cache = {}
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _retry_throttled(fn, attempts=5):
        delays = [3, 6, 12, 24, 30]
        last_exc = None
        for attempt in range(attempts):
            try:
                return fn()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code not in _THROTTLE_CODES:
                    raise
                last_exc = exc
                time.sleep(delays[min(attempt, len(delays) - 1)])
        raise last_exc

    def _error(fn, attempts=5):
        delays = [3, 6, 12, 24, 30]
        for attempt in range(attempts):
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                code = err.get("Code")
                if code not in _THROTTLE_CODES:
                    return code, err.get("Message")
                time.sleep(delays[min(attempt, len(delays) - 1)])
                continue
            raise AssertionError(
                f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
            )
        raise AssertionError(f"gave up after {attempts} attempts, still throttled")

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

    def _setup_network(num_subnets=2):
        if _net_cache:
            return _net_cache["net"]
        default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
        if default_vpcs:
            vpc_id = default_vpcs[0]["VpcId"]
            subnets = ec2.describe_subnets(Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ])["Subnets"]
            per_az = {}
            for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
                per_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
            subnet_ids = [per_az[az] for az in sorted(per_az)][:num_subnets]
            if len(subnet_ids) >= min(num_subnets, 2):
                _net_cache["net"] = (vpc_id, subnet_ids)
                return _net_cache["net"]
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
        try:
            ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}])
        except Exception:
            pass
        azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        subnet_ids = []
        for i in range(num_subnets):
            az = azs[i % len(azs)]["ZoneName"]
            sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
            subnet_ids.append(sid)
            ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        _net_cache["net"] = (vpc_id, subnet_ids)
        return _net_cache["net"]

    def _create_load_balancer(name=None, subnet_ids=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-lb-"))
        if subnet_ids is None:
            _, subnet_ids = _setup_network()
        params = dict(
            Name=name,
            Subnets=subnet_ids,
            Type=kwargs.pop("Type", "application"),
            Scheme=kwargs.pop("Scheme", "internal"),
            Tags=kwargs.pop("Tags", _tags_kv()),
        )
        params.update(kwargs)
        lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
        arn = lb["LoadBalancerArn"]
        ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerArn=arn))
        return lb

    def _create_target_group(name=None, vpc_id=None, **kwargs):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-tg-"))
        params = dict(Name=name, Protocol="HTTP", Port=80, TargetType="ip")
        params.update(kwargs)
        if params.get("TargetType") != "lambda":
            if vpc_id is None:
                vpc_id, _ = _setup_network()
            params.setdefault("VpcId", vpc_id)
        elif vpc_id is not None:
            params["VpcId"] = vpc_id
        params.setdefault("Tags", _tags_kv())
        tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
        arn = tg["TargetGroupArn"]
        ctx.on_cleanup(lambda: _delete_target_group_when_free(elb, arn))
        return tg

    def _create_listener(load_balancer_arn, **kwargs):
        params = dict(LoadBalancerArn=load_balancer_arn, Protocol="HTTP", Port=80)
        params.update(kwargs)
        listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
        arn = listener["ListenerArn"]
        ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=arn))
        return listener

    def _wait_for_lb_active(arn, timeout_s=230, interval_s=10):
        return _poll_until(
            lambda: elb.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0],
            lambda lb: lb["State"]["Code"] in ("active", "active_impaired", "failed"),
            timeout_s=timeout_s, interval_s=interval_s,
            description="load balancer reaching a terminal state",
        )

    s3 = ctx.client("s3")

    def _create_s3_object(body, key="bundle.pem"):
        bucket = _clamp_name(ctx.unique_name("sim2real-behav-ts-bkt-"), 60).lower()
        create_kwargs = {"Bucket": bucket}
        if ctx.region != "us-east-1":
            create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
        s3.create_bucket(**create_kwargs)

        def _cleanup_bucket(b=bucket):
            try:
                objs = s3.list_objects_v2(Bucket=b).get("Contents", [])
                for o in objs:
                    s3.delete_object(Bucket=b, Key=o["Key"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                    raise
            s3.delete_bucket(Bucket=b)

        ctx.on_cleanup(_cleanup_bucket)
        s3.put_object(Bucket=bucket, Key=key, Body=body)
        return bucket, key

    def _openssl(args, timeout=30):
        import subprocess
        require_tools("openssl")
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=timeout)

    def _generate_root_ca(cn="sim2real-behav-ca"):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            key_path = _os.path.join(d, "ca-key.pem")
            cert_path = _os.path.join(d, "ca-cert.pem")
            _openssl([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-subj", f"/CN={cn}",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            ])
            with open(cert_path) as f:
                cert_pem = f.read()
            with open(key_path) as f:
                key_pem = f.read()
        return cert_pem, key_pem

    def _generate_self_signed_cert(cn="sim2real-behav.test"):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            key_path = _os.path.join(d, "key.pem")
            cert_path = _os.path.join(d, "cert.pem")
            _openssl([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-subj", f"/CN={cn}",
            ])
            with open(cert_path) as f:
                cert_pem = f.read()
            with open(key_path) as f:
                key_pem = f.read()
        return cert_pem, key_pem

    acm = ctx.client("acm")

    def _import_acm_cert(cn="sim2real-behav.test"):
        cert_pem, key_pem = _generate_self_signed_cert(cn)
        arn = acm.import_certificate(
            Certificate=cert_pem.encode(), PrivateKey=key_pem.encode()
        )["CertificateArn"]
        ctx.on_cleanup(lambda: _delete_when_released(
            lambda: acm.delete_certificate(CertificateArn=arn), "ResourceInUseException"))
        return arn

    def _wait_trust_store_active(arn, timeout_s=60):
        return _poll_until(
            lambda: elb.describe_trust_stores(TrustStoreArns=[arn])["TrustStores"][0],
            lambda ts: ts["Status"] == "ACTIVE",
            timeout_s=timeout_s, interval_s=2.0,
            description="trust store reaching ACTIVE",
        )

    def _create_trust_store_with_ca(name=None):
        name = _clamp_name(name or ctx.unique_name("sim2real-behav-ts-"))
        ca_cert_pem, ca_key_pem = _generate_root_ca()
        bucket, key = _create_s3_object(ca_cert_pem.encode(), key="ca-bundle.pem")
        resp = _retry_throttled(lambda: elb.create_trust_store(
            Name=name,
            CaCertificatesBundleS3Bucket=bucket,
            CaCertificatesBundleS3Key=key,
            Tags=_tags_kv(),
        ))
        ts = resp["TrustStores"][0]
        arn = ts["TrustStoreArn"]
        ctx.on_cleanup(lambda: _delete_when_released(
            lambda: elb.delete_trust_store(TrustStoreArn=arn), "TrustStoreInUse", timeout_s=120.0))
        ts = _wait_trust_store_active(arn)
        return ts, ca_cert_pem, ca_key_pem

    ts, _ca_cert, _ca_key = _create_trust_store_with_ca()
    ts_arn = ts["TrustStoreArn"]

    lb = _create_load_balancer()
    lb_arn = lb["LoadBalancerArn"]
    cert_arn = _import_acm_cert("sim2real-behav-mtls2.test")
    listener = _create_listener(
        lb_arn, Protocol="HTTPS", Port=443,
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain"}}],
        Certificates=[{"CertificateArn": cert_arn}],
        SslPolicy="ELBSecurityPolicy-2016-08",
        MutualAuthentication={"Mode": "verify", "TrustStoreArn": ts_arn},
    )
    listener_arn = listener["ListenerArn"]

    assocs = _poll_until(
        lambda: elb.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda a: any(x["ResourceArn"] == lb_arn for x in a),
        timeout_s=30, interval_s=2.0, description="load balancer associated with trust store",
    )
    assert any(x["ResourceArn"] == lb_arn for x in assocs), assocs

    code, message = _error(
        lambda: elb.delete_shared_trust_store_association(TrustStoreArn=ts_arn, ResourceArn=lb_arn)
    )
    assert code == "DeleteAssociationSameAccount", (
        f"expected DeleteAssociationSameAccount, got {code!r}"
    )
    expected_message = (
        f"Cannot remove the association because the trust store ARN '{ts_arn}' and resource ARN "
        f"'{lb_arn}' belong to the same account"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected delete must not have touched the association: an independent read, through a
    # different operation than the one that was rejected, still shows the load balancer attached.
    assocs_after_reject = elb.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    assert any(x["ResourceArn"] == lb_arn for x in assocs_after_reject), (
        f"the rejected same-account delete removed the association anyway: {assocs_after_reject!r}"
    )

    # Positive control: the supported way to remove a same-account association -- turning mutual
    # auth off on the listener -- actually works and is observable independently. This is what
    # distinguishes "DeleteSharedTrustStoreAssociation is refused because it's the wrong operation
    # for a same-account association" from "this trust store's associations can never be removed".
    elb.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})
    assocs_after_detach = _poll_until(
        lambda: elb.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"],
        lambda a: not any(x["ResourceArn"] == lb_arn for x in a),
        timeout_s=30, interval_s=2.0,
        description="load balancer disassociated from trust store after mutual auth is turned off",
    )
    assert not any(x["ResourceArn"] == lb_arn for x in assocs_after_detach), (
        f"association still present after detaching mutual auth: {assocs_after_detach!r}"
    )


# Subnet / security group / VPC deletes fail with DependencyViolation while AWS-managed ENIs of an
# asynchronously deleted resource (e.g. a load balancer) remain, so wait (bounded) for them to go,
# retry inside one shared window, and finally raise naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
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
        _time.sleep(10)
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
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


# Teardown-only: a listener / load balancer delete releases its certificate and trust store
# association asynchronously, so their deletes retry the in-use refusal (bounded) before failing.
def _delete_when_released(fn, in_use_code, timeout_s=300.0, interval_s=10.0):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except _ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != in_use_code or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
