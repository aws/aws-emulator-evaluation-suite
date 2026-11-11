"""resource-policy-not-found."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError


from fidelity_tests_runner import require_tools
from behavioral_harness import tags

CHECK = "resource-policy-not-found"
GROUP = 'overly-permissive'
SERVICES = ['elbv2']

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")

@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a live trust store with no policy succeeds and returns no policy, but
    fails with ResourceNotFound for a never-created trust store ARN instead of an empty policy."""

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

    def _error(fn):
        """Call fn(), retrying throttling; return its error (code, message). A success raises."""
        delays = [3, 6, 12, 24, 30]
        for attempt in range(5):
            try:
                result = fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                if err.get("Code") in _THROTTLE_CODES:
                    time.sleep(delays[attempt])
                    continue
                return err.get("Code"), err.get("Message")
            raise AssertionError(f"expected rejection but the call SUCCEEDED and returned {result!r}")
        raise AssertionError("exhausted retries on throttling")

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
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
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
            ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
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

    _ids = {}

    def _account_id():
        if "acct" not in _ids:
            _ids["acct"] = ctx.client("sts").get_caller_identity()["Account"]
        return _ids["acct"]

    def _fake_lb_arn(lb_type="app"):
        return (f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:"
                f"loadbalancer/{lb_type}/sim2real-behav-missing/0000000000000000")

    def _fake_listener_arn(lb_type="app"):
        return (f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:"
                f"listener/{lb_type}/sim2real-behav-missing/0000000000000000/1111111111111111")

    def _fake_tg_arn():
        return (f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:"
                "targetgroup/sim2real-behav-missing/0000000000000000")

    def _fake_trust_store_arn():
        return (f"arn:aws:elasticloadbalancing:{ctx.region}:{_account_id()}:"
                "truststore/sim2real-behav-missing/0000000000000000")

    s3 = ctx.client("s3")

    def _create_s3_object(body, key="bundle.pem"):
        bucket = _clamp_name(ctx.unique_name("sim2real-behav-ts-bkt-"), 60).lower()
        create_kwargs = {"Bucket": bucket}
        # S3 CreateBucket rejects an explicit LocationConstraint in us-east-1.
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
        ctx.on_cleanup(lambda: elb.delete_trust_store(TrustStoreArn=arn))
        ts = _wait_trust_store_active(arn)
        return ts, ca_cert_pem, ca_key_pem

    ts, _ca_cert, _ca_key = _create_trust_store_with_ca()

    def _no_policy(r):
        # ELBv2 returns Policy as the string '{}' when none is attached; treat any empty form as none.
        import json
        pol = r.get("Policy")
        if not pol:
            return True
        try:
            return not json.loads(pol)
        except Exception:
            return False

    resp = _retry_throttled(lambda: elb.get_resource_policy(ResourceArn=ts["TrustStoreArn"]))
    assert isinstance(resp, dict), f"expected a dict response for an existing trust store, got {resp!r}"
    assert _no_policy(resp), f"expected no attached policy on a freshly created trust store, got {resp!r}"

    fake_arn = _fake_trust_store_arn()
    code, message = _error(lambda: elb.get_resource_policy(ResourceArn=fake_arn))
    assert code == "ResourceNotFound", (
        f"expected ResourceNotFound for a fabricated/never-created trust-store ARN, got {code!r}"
    )
    expected = f"Trust store ARN '{fake_arn}' not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"



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
