"""outbound-dns-resolution-failure-for-unresolvable-hostname-rejected."""

from __future__ import annotations

import io
import json
import re
import textwrap
import time
import zipfile

from behavioral_harness import tags


CHECK = "outbound-dns-resolution-failure-for-unresolvable-hostname-rejected"
GROUP = 'networking'
SERVICES = ['lambda']

# RFC 2606 reserves example.com for documentation; it is guaranteed to exist and resolve, with
# no dependency on this account or this run. Used as the positive control.
GOOD_HOST = "example.com"
# RFC 2606 reserves the .invalid TLD, guaranteeing it never resolves anywhere.
BAD_HOST = "sim2real-dns-does-not-exist.invalid"

HANDLER = """\
import socket


def handler(event, context):
    host = event["host"]
    try:
        address = socket.gethostbyname(host)
    except OSError as exc:
        return {"resolved": False, "error_type": type(exc).__name__, "error": str(exc)}
    return {"resolved": True, "address": address}
"""

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _create_role(ctx):
    """An execution role this check creates (Lambda trust + basic logging), removed at cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-exec-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_LAMBDA_TRUST,
                          Tags=[{"Key": "sim2real:managed", "Value": "true"}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only the fresh-role refusal ("cannot be assumed") for at most 90 s."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3.0)  # a role created seconds ago is not yet assumable by Lambda
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    """Delete the function and its log group; an already-absent one is done, anything else raises."""
    from botocore.exceptions import ClientError

    for delete in (lambda: lam.delete_function(FunctionName=name),
                   lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")):
        try:
            delete()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _wait_active(lam, fn, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return last
        time.sleep(1.0)
    raise AssertionError(f"{fn} did not reach State=Active within {timeout_s}s. Last: {last!r}")


def _invoke(lam, fn, host):
    resp = lam.invoke(FunctionName=fn, Payload=json.dumps({"host": host}).encode("utf-8"))
    raw = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"Invoke StatusCode {resp['StatusCode']!r}, payload {raw!r}"
    assert "FunctionError" not in resp, f"handler failed with {resp.get('FunctionError')!r}: {raw!r}"
    return json.loads(raw)


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Outbound DNS inside the sandbox fails with socket.gaierror for an RFC 2606 .invalid host,
    while example.com resolves to an IPv4 address from the same function.
    """
    lam = ctx.client("lambda")

    name = ctx.unique_name("sim2real-behav-baddns-")
    _create_function(lam,
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_create_role(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=128, Timeout=30, Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)

    # Positive control: the same function, the same code path, a host that must resolve.
    control = _invoke(lam, name, GOOD_HOST)
    assert control.get("resolved") is True, (
        f"positive control failed: {GOOD_HOST!r} did not resolve inside the sandbox: {control!r}"
    )
    assert isinstance(control.get("address"), str) and _IPV4_RE.match(control["address"]), (
        f"positive control returned a non-IPv4 address for {GOOD_HOST!r}: {control!r}"
    )

    # Break exactly one thing: a hostname under a TLD RFC 2606 reserves as permanently
    # unresolvable, so this is a service/sandbox fidelity fact, never a transient DNS blip.
    broken = _invoke(lam, name, BAD_HOST)
    assert broken.get("resolved") is False, (
        f"DNS resolution for {BAD_HOST!r} must fail — .invalid is reserved by RFC 2606 to never "
        f"resolve — but the sandbox reported {broken!r}, which means outbound DNS is faked rather "
        f"than real"
    )
    assert broken.get("address") is None, (
        f"a failed resolution must carry no address, got {broken!r}"
    )
    assert broken.get("error_type") == "gaierror", (
        f"expected socket.gaierror (the real getaddrinfo failure class) for {BAD_HOST!r}, got "
        f"error_type={broken.get('error_type')!r} ({broken.get('error')!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
