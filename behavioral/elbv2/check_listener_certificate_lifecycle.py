"""listener-certificate-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from fidelity_tests_runner import require_tools
from behavioral_harness import tags

CHECK = "listener-certificate-lifecycle"
GROUP = 'listener-lifecycle'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddListenerCertificates attaches a cert visible via Describe; RemoveListenerCertificates detaches it again without dropping the default cert."""

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

    def _error_code(fn):
        delays = [3, 6, 12, 24, 30]
        code = None
        for attempt in range(5):
            try:
                fn()
                code = None
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
            if code not in _THROTTLE_CODES:
                return code
            time.sleep(delays[attempt])
        return code

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
        azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
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
        ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=arn))
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

    def _delete_cert_with_retry(cert_arn, attempts=6):
        # ACM still reports a certificate as in-use for a few seconds after the listener
        # that referenced it is deleted (detachment is asynchronous), so an immediate
        # DeleteCertificate can raise ResourceInUseException even though the listener is
        # already gone. Bounded retry within on_cleanup's 60s budget, mirroring the same
        # detach-lag pattern ELBv2/EC2 delete ordering hits elsewhere in this suite.
        delays = [1, 2, 3, 5, 5, 5]
        last_exc = None
        for attempt in range(attempts):
            try:
                acm.delete_certificate(CertificateArn=cert_arn)
                return
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
                    raise
                last_exc = exc
                time.sleep(delays[min(attempt, len(delays) - 1)])
        raise last_exc

    def _import_acm_cert(cn="sim2real-behav.test"):
        cert_pem, key_pem = _generate_self_signed_cert(cn)
        arn = acm.import_certificate(
            Certificate=cert_pem.encode(), PrivateKey=key_pem.encode(),
            Tags=_tags_kv(),
        )["CertificateArn"]
        ctx.on_cleanup(lambda: _delete_cert_with_retry(arn))
        return arn

    lb = _create_load_balancer()
    default_cert_arn = _import_acm_cert("sim2real-behav-default.test")
    extra_cert_arn = _import_acm_cert("sim2real-behav-extra.test")

    listener = _create_listener(
        lb["LoadBalancerArn"], Protocol="HTTPS", Port=443,
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain"}}],
        Certificates=[{"CertificateArn": default_cert_arn}],
        SslPolicy="ELBSecurityPolicy-2016-08",
    )
    listener_arn = listener["ListenerArn"]

    initial = elb.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"]
    initial_by_arn = {c["CertificateArn"]: c for c in initial}
    assert set(initial_by_arn) == {default_cert_arn}, (
        f"expected only the default certificate {default_cert_arn} on a freshly created "
        f"listener, got {sorted(initial_by_arn)}"
    )
    assert initial_by_arn[default_cert_arn].get("IsDefault") is True, (
        f"expected IsDefault=True for the default certificate {default_cert_arn}, "
        f"got {initial_by_arn[default_cert_arn]!r}"
    )

    elb.add_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )

    attached = _poll_until(
        lambda: elb.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"],
        lambda cs: any(c["CertificateArn"] == extra_cert_arn for c in cs),
        timeout_s=30, interval_s=2.0, description="extra certificate attached",
    )
    attached_by_arn = {c["CertificateArn"]: c for c in attached}
    assert default_cert_arn in attached_by_arn and extra_cert_arn in attached_by_arn, (
        f"expected both {default_cert_arn} and {extra_cert_arn} attached after "
        f"AddListenerCertificates, got {sorted(attached_by_arn)}"
    )
    assert attached_by_arn[default_cert_arn].get("IsDefault") is True, (
        f"expected the original certificate to remain IsDefault=True after the add, "
        f"got {attached_by_arn[default_cert_arn]!r}"
    )
    assert attached_by_arn[extra_cert_arn].get("IsDefault") is not True, (
        f"expected the newly attached certificate {extra_cert_arn} to be non-default, "
        f"got {attached_by_arn[extra_cert_arn]!r}"
    )

    elb.remove_listener_certificates(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": extra_cert_arn}]
    )

    remaining = _poll_until(
        lambda: elb.describe_listener_certificates(ListenerArn=listener_arn)["Certificates"],
        lambda cs: not any(c["CertificateArn"] == extra_cert_arn for c in cs),
        timeout_s=30, interval_s=2.0, description="extra certificate removed",
    )
    remaining_by_arn = {c["CertificateArn"]: c for c in remaining}
    assert extra_cert_arn not in remaining_by_arn, (
        f"expected {extra_cert_arn} to be detached after RemoveListenerCertificates, "
        f"still present: {sorted(remaining_by_arn)}"
    )
    assert remaining_by_arn.get(default_cert_arn, {}).get("IsDefault") is True, (
        f"expected the default certificate {default_cert_arn} to remain attached and "
        f"IsDefault=True after removing the extra certificate, got "
        f"{remaining_by_arn.get(default_cert_arn)!r}"
    )


# ===== helpers =====

# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
