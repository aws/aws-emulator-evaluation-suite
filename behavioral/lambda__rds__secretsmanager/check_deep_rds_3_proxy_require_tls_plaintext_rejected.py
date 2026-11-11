"""deep-rds-3-proxy-require-tls-plaintext-rejected."""

from __future__ import annotations

import io
import json
import os
import secrets
import string
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-rds-3-proxy-require-tls-plaintext-rejected"
GROUP = "rds-propagation"
SERVICES = ["lambda", "rds", "secretsmanager"]

_PORT = 3306
_MASTER = "s2radmin"
_VPC_OCTET = 183
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real", "Value": "deep-rds-3-proxy-tls"},
]

_HANDLER = r'''
import socket
import ssl
import struct

import pymysql


def _read_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _greeting(host, port):
    """Read the server's initial MySQL handshake packet over a bare TCP socket."""
    s = socket.create_connection((host, port), timeout=10)
    try:
        hdr = _read_exact(s, 4)
        if len(hdr) < 4:
            return {"proto": None, "raw": hdr.hex()}
        n = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
        body = _read_exact(s, n)
    finally:
        s.close()
    if not body:
        return {"proto": None}
    if body[0] == 0xFF:
        return {"proto": 255, "error": body[3:].decode(errors="replace")}
    end = body.index(b"\0", 1)
    p = end + 1 + 4 + 8 + 1
    caps = struct.unpack("<H", body[p:p + 2])[0]
    return {"proto": body[0], "version": body[1:end].decode(errors="replace"),
            "ssl_capable": bool(caps & 0x0800)}


def handler(event, context):
    host, port = event["host"], int(event["port"])
    out = {"mode": event["mode"], "greeting": _greeting(host, port)}
    kw = dict(host=host, port=port, user=event["user"], password=event["password"],
              connect_timeout=15)
    if event["mode"] == "tls":
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        kw["ssl"] = ctx
    else:
        # pymysql >= 1.1 defaults to PREFERRED (opportunistic TLS whenever the greeting advertises
        # SSL), so omitting ssl options is NOT plaintext. Measured: the "plain" probe negotiated
        # TLSv1.3 through the RequireTLS proxy until this was set.
        kw["ssl_disabled"] = True
    try:
        conn = pymysql.connect(**kw)
    except pymysql.err.MySQLError as exc:
        args = list(exc.args)
        out.update(ok=False, cls=type(exc).__name__,
                   errno=args[0] if args and isinstance(args[0], int) else None,
                   msg=str(args[1]) if len(args) > 1 else str(exc))
        return out
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT %s", (event["marker"],))
            out["echo"] = cur.fetchone()[0]
        sock = conn._sock
        out["tls_version"] = sock.version() if isinstance(sock, ssl.SSLSocket) else None
        out["ok"] = True
    finally:
        conn.close()
    return out
'''


# ===== helpers =====
def _poll_until(probe, pred, *, timeout_s, interval_s, description, ctx=None):
    """Poll probe() until pred(value); RAISE on the deadline, never return the last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description} was not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# Codes a delete returns while a dependency is still being released.
_IN_USE_CODES = frozenset({
    "DependencyViolation", "InvalidGroup.InUse", "InvalidDBInstanceState",
    "InvalidDBProxyStateFault", "InvalidDBSubnetGroupStateFault",
})


def _retry_delete(fn, *tolerated_codes, timeout_s=900, interval_s=2, what="", before=None):
    """Delete, retrying only while a dependency still holds it; return on not-found, raise the rest."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        if before is not None:
            before()
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in tolerated_codes:
                return
            if code not in _IN_USE_CODES:
                raise
            last = code
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{what or fn!r} not deleted, last error {last!r}")
        time.sleep(interval_s)


def _password():
    alphabet = string.ascii_letters + string.digits
    return "S2r" + "".join(secrets.choice(alphabet) for _ in range(29))


def _reap_detached_enis(ec2, vpc_id):
    """Delete ENIs left `available` in this check's own VPC (Lambda/RDS release them detached)."""
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                     {"Name": "status", "Values": ["available"]}]):
        for eni in page.get("NetworkInterfaces", []):
            try:
                ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
            except ClientError as exc:
                # Gone, re-attached or service-managed: the dependent delete retries and reaps again.
                if exc.response.get("Error", {}).get("Code") not in (
                        "InvalidNetworkInterfaceID.NotFound", "InvalidNetworkInterface.InUse",
                        "OperationNotPermitted"):
                    raise


def _network(ctx):
    """A dedicated VPC with private subnets in two AZs and one self-referencing SG on 3306."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{_VPC_OCTET}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound", what=f"vpc {vpc_id}",
        before=lambda: _reap_detached_enis(ec2, vpc_id)))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc_id], WaiterConfig={"Delay": 1, "MaxAttempts": 120})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    zones = ec2.describe_availability_zones(Filters=[
        {"Name": "state", "Values": ["available"]},
        {"Name": "opt-in-status", "Values": ["opt-in-not-required"]},
    ])["AvailabilityZones"]
    azs = sorted(z["ZoneName"] for z in zones)
    assert len(azs) >= 2, f"a proxy and a DB subnet group need 2 AZs; {ctx.region} offered {azs!r}"

    subnet_ids = []
    for index, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.{_VPC_OCTET}.{index}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet_id: _retry_delete(
            lambda: ec2.delete_subnet(SubnetId=s), "InvalidSubnetID.NotFound",
            what=f"subnet {s}", timeout_s=1200, before=lambda: _reap_detached_enis(ec2, vpc_id)))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-pxtls-sg-"),
        Description="sim2real proxy RequireTLS data plane", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_security_group(GroupId=sg_id), "InvalidGroup.NotFound",
        what=f"security group {sg_id}", timeout_s=1200,
        before=lambda: _reap_detached_enis(ec2, vpc_id)))
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": _PORT, "ToPort": _PORT,
        "UserIdGroupPairs": [{"GroupId": sg_id, "Description": "lambda/proxy/db in this SG"}],
    }])

    group_name = ctx.unique_name("sim2real-pxtls-subnets-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=group_name, DBSubnetGroupDescription="sim2real proxy TLS subnets",
        SubnetIds=subnet_ids, Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=group_name),
        "DBSubnetGroupNotFoundFault", what=f"db subnet group {group_name}"))
    return vpc_id, subnet_ids, sg_id, group_name


def _instance(rds, inst_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
            return None
        raise


def _delete_instance(rds, inst_id):
    _retry_delete(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True),
        "DBInstanceNotFound", what=f"db instance {inst_id}")
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        last = _instance(rds, inst_id)
        if last is None:
            return
        time.sleep(2)
    raise RuntimeError(f"db instance {inst_id} was not deleted: {last.get('DBInstanceStatus')!r}")


def _proxy(rds, name):
    try:
        return rds.describe_db_proxies(DBProxyName=name)["DBProxies"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBProxyNotFoundFault":
            return None
        raise


def _delete_proxy(rds, name):
    _retry_delete(lambda: rds.delete_db_proxy(DBProxyName=name), "DBProxyNotFoundFault",
                  what=f"db proxy {name}", timeout_s=300)
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        last = _proxy(rds, name)
        if last is None:
            return
        time.sleep(2)
    raise RuntimeError(f"db proxy {name} was not deleted: {last.get('Status')!r}")


def _default_engine_version(rds, engine):
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
        "DBEngineVersions", [])
    assert versions, f"no default {engine!r} engine version is orderable in {rds.meta.region_name}"
    return versions[0]


def _orderable_class(rds, engine, version):
    classes = set()
    for page in rds.get_paginator("describe_orderable_db_instance_options").paginate(
            Engine=engine, EngineVersion=version):
        for opt in page.get("OrderableDBInstanceOptions", []):
            classes.add(opt["DBInstanceClass"])
    for want in ("db.t4g.micro", "db.t3.micro", "db.t4g.small", "db.t3.small"):
        if want in classes:
            return want
    raise AssertionError(f"no small orderable class for {engine} {version}: {sorted(classes)!r}")


def _iam_role(ctx, service, *, managed=(), inline=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-pxtls-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service},
                       "Action": "sts:AssumeRole"}],
    }), Tags=_TAGS)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    for policy_arn in managed:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p))
    if inline:
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": inline}))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn


def _build_zip():
    import pymysql

    root = os.path.dirname(pymysql.__file__)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _HANDLER)
        for dirpath, _dirs, files in os.walk(root):
            for fname in files:
                if fname.endswith(".py"):
                    full = os.path.join(dirpath, fname)
                    zf.write(full, "pymysql/" + os.path.relpath(full, root).replace(os.sep, "/"))
    return buf.getvalue()


def _reap_log_group(logs, name, rounds=10):
    """A buffered stream can recreate the group after the function is gone, so reap in a loop."""
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError:
            pass
        time.sleep(2)
        groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        if not any(g["logGroupName"] == name for g in groups):
            return
    raise RuntimeError(f"log group {name} kept reappearing")


def _invoke(lam, name, payload):
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse",
                      Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read() or b"null")
    assert not resp.get("FunctionError"), f"the probe Lambda itself crashed: {body!r}"
    return body
# ===== end helpers =====


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:native",
      "plane:data")
# tls-subject: the check asserts the proxy refuses plaintext and serves verified TLS.
def run(ctx) -> None:
    """A RequireTLS=True proxy refuses a plaintext MySQL login with a server-sent error while a
    verified TLS login succeeds; flipping only RequireTLS to False admits the same plaintext login.
    """
    import pymysql  # noqa: F401 — vendored into the probe Lambda below
    # The proxy endpoint is VPC-private, so the MySQL client runs in a Lambda inside its VPC.

    rds = ctx.client("rds")
    sm = ctx.client("secretsmanager")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    engine = "mysql"
    ver = _default_engine_version(rds, engine)
    version = ver["EngineVersion"]
    klass = _orderable_class(rds, engine, version)
    password = _password()
    zip_bytes = _build_zip()

    try:
        vpc_id, subnet_ids, sg_id, subnet_group = _network(ctx)

        # RDS assumes this service-linked role to place the proxy's ENIs. Create-or-adopt and
        # never delete: it is an account-level singleton other checks also depend on.
        try:
            iam.create_service_linked_role(AWSServiceName="rds.amazonaws.com")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInput":
                raise

        inst_id = ctx.unique_name("sim2real-pxtls-db-")
        rds.create_db_instance(
            DBInstanceIdentifier=inst_id, Engine=engine, EngineVersion=version,
            DBInstanceClass=klass, AllocatedStorage=20, MasterUsername=_MASTER,
            MasterUserPassword=password, DBSubnetGroupName=subnet_group,
            VpcSecurityGroupIds=[sg_id], BackupRetentionPeriod=0, PubliclyAccessible=False,
            DeletionProtection=False, Tags=_TAGS,
        )
        ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

        secret_arn = sm.create_secret(
            Name=ctx.unique_name("sim2real-pxtls-secret-"),
            SecretString=json.dumps({"username": _MASTER, "password": password}), Tags=_TAGS,
        )["ARN"]
        ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn,
                                                ForceDeleteWithoutRecovery=True))
        proxy_role = _iam_role(ctx, "rds.amazonaws.com", inline=[{
            "Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}])

        proxy_name = ctx.unique_name("sim2real-pxtls-")
        # The proxy role is minutes old: CreateDBProxy rejects a not-yet-assumable role with
        # InvalidParameterValue, so that one code is retried, bounded.
        deadline = time.monotonic() + _budget_s(ctx, 180)
        while True:
            try:
                rds.create_db_proxy(
                    DBProxyName=proxy_name, EngineFamily="MYSQL",
                    Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED",
                           "ClientPasswordAuthType": "MYSQL_NATIVE_PASSWORD"}],
                    RoleArn=proxy_role, VpcSubnetIds=subnet_ids, VpcSecurityGroupIds=[sg_id],
                    RequireTLS=True, Tags=_TAGS)
                break
            except ClientError as exc:
                if (exc.response.get("Error", {}).get("Code") != "InvalidParameterValue"
                        or time.monotonic() >= deadline):
                    if exc.response.get("Error", {}).get("Code") == "InvalidParameterValue" and _budget_spent(ctx):
                        raise TimeoutError("CreateDBProxy to accept the fresh role: the run budget ended first; not graded") from exc
                    raise
                time.sleep(2)
        ctx.on_cleanup(lambda: _delete_proxy(rds, proxy_name))

        fn_role = _iam_role(ctx, "lambda.amazonaws.com", managed=[
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"])
        fn_name = ctx.unique_name("sim2real-pxtls-fn-")
        ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))
        deadline = time.monotonic() + _budget_s(ctx, 180)
        while True:
            try:
                lam.create_function(
                    FunctionName=fn_name, Runtime="python3.12", Role=fn_role,
                    Handler="index.handler", Code={"ZipFile": zip_bytes}, Timeout=60,
                    MemorySize=256, VpcConfig={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
                    Tags={"sim2real": "deep-rds-3-proxy-tls"})
                break
            except ClientError as exc:
                if (exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException"
                        or time.monotonic() >= deadline):
                    if exc.response.get("Error", {}).get("Code") == "InvalidParameterValueException" and _budget_spent(ctx):
                        raise TimeoutError("CreateFunction to accept the fresh role: the run budget ended first; not graded") from exc
                    raise
                time.sleep(2)
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

        _poll_until(lambda: _instance(rds, inst_id),
                    lambda i: i is not None and i.get("DBInstanceStatus") == "available",
                    timeout_s=_budget_s(ctx, 1500), interval_s=2,
                    ctx=ctx, description=f"db instance {inst_id} reaching 'available'")
        proxy = _poll_until(lambda: _proxy(rds, proxy_name),
                            lambda p: p is not None and p.get("Status") == "available",
                            timeout_s=_budget_s(ctx, 900), interval_s=2,
                            ctx=ctx, description=f"proxy {proxy_name} reaching 'available'")
        assert proxy.get("RequireTLS") is True, (
            f"the proxy must report RequireTLS=True; got {proxy.get('RequireTLS')!r}")
        rds.register_db_proxy_targets(DBProxyName=proxy_name, DBInstanceIdentifiers=[inst_id])
        _poll_until(
            lambda: [t.get("TargetHealth", {}).get("State") for t in rds.describe_db_proxy_targets(
                DBProxyName=proxy_name)["Targets"] if t.get("Type") == "RDS_INSTANCE"],
            lambda states: states == ["AVAILABLE"], timeout_s=_budget_s(ctx, 900), interval_s=2,
            ctx=ctx, description=f"proxy {proxy_name}'s instance target AVAILABLE")
        lam.get_waiter("function_active_v2").wait(
            FunctionName=fn_name, WaiterConfig={"Delay": 1, "MaxAttempts": 300})
        endpoint, port = proxy["Endpoint"], _PORT
        base = {"host": endpoint, "port": port, "user": _MASTER, "password": password}

        # --- 3. positive control: verified TLS through the proxy.
        marker = ctx.unique_name("s2r-tls-")
        tls = _poll_until(lambda: _invoke(lam, fn_name, dict(base, mode="tls", marker=marker)),
                          lambda r: r.get("ok") is True, timeout_s=_budget_s(ctx, 300),
                          interval_s=2, ctx=ctx, description="a verified TLS login through the proxy")
        print(f"[measure] tls through proxy: {tls!r}")
        assert tls.get("echo") == marker, f"the TLS session must run SQL; got {tls!r}"
        assert str(tls.get("tls_version") or "").startswith("TLSv1"), (
            f"the client socket must be TLS; got {tls.get('tls_version')!r}")

        # --- 4. negative: same login, no TLS.
        plain = _invoke(lam, fn_name, dict(base, mode="plain", marker=ctx.unique_name("s2r-pt-")))
        print(f"[measure] plaintext through RequireTLS proxy: {plain!r}")
        greeting = plain.get("greeting") or {}
        assert greeting.get("proto") == 10 and greeting.get("ssl_capable") is True, (
            f"the proxy must answer TCP with a MySQL v10 greeting advertising SSL; got {greeting!r}")
        assert plain.get("ok") is False, (
            f"a plaintext login through a RequireTLS=True proxy must be refused; got {plain!r}")

        # --- 5. break-then-restore: only RequireTLS changes.
        rds.modify_db_proxy(DBProxyName=proxy_name, RequireTLS=False)
        _poll_until(lambda: _proxy(rds, proxy_name),
                    lambda p: p is not None and p.get("Status") == "available"
                    and p.get("RequireTLS") is False, timeout_s=_budget_s(ctx, 600), interval_s=2,
                    ctx=ctx, description=f"proxy {proxy_name} available with RequireTLS=False")
        marker2 = ctx.unique_name("s2r-pt-")
        admitted = _poll_until(
            lambda: _invoke(lam, fn_name, dict(base, mode="plain", marker=marker2)),
            lambda r: r.get("ok") is True, timeout_s=_budget_s(ctx, 300), interval_s=2,
            ctx=ctx, description="the plaintext login admitted once RequireTLS=False")
        assert admitted.get("echo") == marker2 and admitted.get("tls_version") is None, (
            f"with RequireTLS=False the plaintext session must run SQL unencrypted; got {admitted!r}")
        # Asserted last so every beat above has run: one exact server-sent error, never a client-side
        # CR_* code (2000-2999), which would mean the client gave up before the proxy decided.
        assert (plain.get("cls"), plain.get("errno")) == ("OperationalError", 3159), (
            f"the refusal must be the server-sent error; got {plain!r}")
    finally:
        # Drain teardown inside the check's budget: post-check cleanup is bounded at 60s, which a
        # proxy + instance + Lambda-ENI + VPC teardown cannot fit; a cut-off chain strands the VPC.
        ctx.run_cleanups()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
