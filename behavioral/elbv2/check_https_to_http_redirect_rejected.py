"""https-to-http-redirect-rejected."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "https-to-http-redirect-rejected"
GROUP = "listener-rules"
SERVICES = ["elbv2"]

_DOWNGRADE_MSG = "You cannot redirect HTTPS to HTTP."
# Port 8080 avoids a self-redirect loop on HTTP:80, so only the listener protocol differs
# between the rejected and the accepted call. The model's RedirectActionProtocol pattern
# admits "HTTP"; the rejection is a cross-resource rule, not request validation.
_TO_HTTP = {
    "Type": "redirect",
    "RedirectConfig": {"Protocol": "HTTP", "Port": "8080", "StatusCode": "HTTP_302"},
}


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An HTTPS->HTTP redirect is rejected with InvalidLoadBalancerAction on an HTTPS listener
    (CreateRule and ModifyListener), while the same redirect is accepted on an HTTP listener.
    """
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    elbv2 = ctx.client("elbv2")
    tag = ctx.unique_name("sim2real-behav-elbv2rule-")

    # --- network: a dedicated VPC, two subnets in two derived AZs (no default VPC) ---
    vpc_id = ec2.create_vpc(
        CidrBlock="10.87.0.0/16", TagSpecifications=[_tag_spec("vpc", tag)]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )
    assert len(azs) >= 2, f"need two available AZs in {ctx.region!r}, found {azs!r}"
    subnets = []
    for i, az in enumerate(azs[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.87.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", tag)],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _retry_dependency(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnets.append(sid)

    # --- certificate: self-signed, minted in memory, imported into ACM ---
    cert_pem, key_pem = _self_signed_pem("sim2real-behav.example.com")
    cert_arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem,
        Tags=[{"Key": "Name", "Value": tag}, {"Key": "sim2real", "Value": CHECK}],
    )["CertificateArn"]
    del key_pem
    # Registered BEFORE the load balancer, so LIFO deletes the LB (and its HTTPS listener)
    # first; until then ACM answers ResourceInUseException, which the helper polls through.
    ctx.on_cleanup(lambda: _retry_in_use(lambda: acm.delete_certificate(CertificateArn=cert_arn)))

    # --- load balancer and two listeners ---
    lb_name = ctx.unique_name("sim2real-behav-rl-")  # 30 chars, LB limit 32
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=subnets, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    not_found = {"Type": "fixed-response",
                 "FixedResponseConfig": {"StatusCode": "404", "ContentType": "text/plain"}}
    https_arn = _create_https_listener(elbv2, lb_arn, cert_arn, not_found)
    http_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=[not_found]
    )["Listeners"][0]["ListenerArn"]

    # --- the negative, twice: CreateRule and ModifyListener on the HTTPS listener ---
    code, msg = _error(lambda: elbv2.create_rule(
        ListenerArn=https_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/plain"]}], Actions=[_TO_HTTP],
    ))
    assert code == "InvalidLoadBalancerAction", (
        f"CreateRule HTTPS->HTTP redirect: expected InvalidLoadBalancerAction, got {code!r} ({msg!r})"
    )
    assert msg == _DOWNGRADE_MSG, f"CreateRule HTTPS->HTTP message was {msg!r}, expected {_DOWNGRADE_MSG!r}"

    code, msg = _error(lambda: elbv2.modify_listener(ListenerArn=https_arn, DefaultActions=[_TO_HTTP]))
    assert code == "InvalidLoadBalancerAction", (
        f"ModifyListener HTTPS->HTTP default action: expected InvalidLoadBalancerAction, got {code!r} ({msg!r})"
    )
    assert msg == _DOWNGRADE_MSG, f"ModifyListener HTTPS->HTTP message was {msg!r}, expected {_DOWNGRADE_MSG!r}"

    # --- effect absent: no rule was added and the default action did not change ---
    rules = elbv2.describe_rules(ListenerArn=https_arn)["Rules"]
    assert [r["IsDefault"] for r in rules] == [True], (
        f"rejected CreateRule left rules behind on the HTTPS listener: {rules!r}"
    )
    listener = elbv2.describe_listeners(ListenerArns=[https_arn])["Listeners"][0]
    assert listener["DefaultActions"][0]["Type"] == "fixed-response", (
        f"rejected ModifyListener changed the default action to {listener['DefaultActions']!r}"
    )

    # --- positive control 1: the IDENTICAL redirect is accepted on the HTTP listener ---
    ok = elbv2.create_rule(
        ListenerArn=http_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/plain"]}], Actions=[_TO_HTTP],
    )["Rules"][0]
    got = ok["Actions"][0]["RedirectConfig"]
    assert (got["Protocol"], got["Port"], got["StatusCode"]) == ("HTTP", "8080", "HTTP_302"), (
        f"HTTP-listener redirect persisted as {got!r}"
    )

    # --- positive control 2: an HTTPS->HTTPS redirect is accepted on the HTTPS listener ---
    ok2 = elbv2.create_rule(
        ListenerArn=https_arn, Priority=20,
        Conditions=[{"Field": "path-pattern", "Values": ["/moved"]}],
        Actions=[{"Type": "redirect", "RedirectConfig": {
            "Protocol": "HTTPS", "Host": "moved.example.com", "StatusCode": "HTTP_301"}}],
    )["Rules"][0]
    got2 = ok2["Actions"][0]["RedirectConfig"]
    assert (got2["Protocol"], got2["Host"], got2["Port"]) == ("HTTPS", "moved.example.com", "#{port}"), (
        f"HTTPS-listener HTTPS redirect persisted as {got2!r}"
    )


# ===== helpers =====
def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": CHECK}]}


def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise AssertionError if it succeeds."""
    try:
        resp = fn()
    except Exception as exc:  # botocore ClientError
        err = getattr(exc, "response", {}).get("Error", {})
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call was ACCEPTED but real AWS rejects it: {resp!r}")


def _create_https_listener(elbv2, lb_arn, cert_arn, default_action):
    """ACM is eventually consistent with ELB: a just-imported certificate can briefly answer
    CertificateNotFound. Poll that one condition, bounded."""
    deadline = time.time() + 120
    while True:
        try:
            return elbv2.create_listener(
                LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443,
                Certificates=[{"CertificateArn": cert_arn}], DefaultActions=[default_action],
            )["Listeners"][0]["ListenerArn"]
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "CertificateNotFound" or time.time() > deadline:
                raise
            time.sleep(5)


def _retry_on(code_wanted, fn, budget_s):
    deadline = time.time() + budget_s
    while True:
        try:
            return fn()
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != code_wanted or time.time() > deadline:
                raise
            time.sleep(2)


def _retry_dependency(fn):
    # ALB ENIs are released asynchronously after DeleteLoadBalancer; the subnet/VPC delete
    # answers DependencyViolation until they are gone.
    return _retry_on("DependencyViolation", fn, 600)


def _retry_in_use(fn):
    return _retry_on("ResourceInUseException", fn, 300)


def _self_signed_pem(common_name):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption()),
    )


# Resources in this VPC (load balancers, endpoints, functions, ...) delete asynchronously and
# leave ENIs behind, so network deletes answer DependencyViolation for a while. Wait, bounded,
# for those ENIs to go, then raise naming any still attached. The window is shared by all of a
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
