"""nodejs24-webcrypto-hmac-sha256-and-aesgcm-round-trip."""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs24-webcrypto-hmac-sha256-and-aesgcm-round-trip"
GROUP = "nodejs-environment"
SERVICES = ["iam", "lambda"]


_RUNTIME = "nodejs24.x"
_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
_MESSAGE = "lambda webcrypto hmac message"
_PLAINTEXT = "lambda webcrypto aesgcm round trip"
_FILES = {"index.js": """\
exports.handler = async (event) => {
  const keyBytes = Buffer.from(event.keyHex, "hex");
  const messageBytes = Buffer.from(event.message, "utf8");

  const hmacKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const sigBuf = await crypto.subtle.sign("HMAC", hmacKey, messageBytes);
  const verified = await crypto.subtle.verify("HMAC", hmacKey, sigBuf, messageBytes);

  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = Buffer.from(event.plaintext, "utf8");
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintextBytes);
  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ctBuf);

  return {
    signatureHex: Buffer.from(sigBuf).toString("hex"),
    signatureLength: sigBuf.byteLength,
    verified,
    decrypted: Buffer.from(ptBuf).toString("utf8"),
  };
};
"""}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nodejs24.x function's crypto.subtle HMAC-SHA256 sign/verify and AES-GCM
    generateKey/encrypt/decrypt match an outside HMAC and round-trip the plaintext.

    Reference: https://nodejs.org/docs/latest-v24.x/api/webcrypto.html
    """
    role = _execution_role(ctx, [])
    fn = _function(ctx, role["arn"], _FILES)
    out = _invoke_ok(ctx, fn["name"], {
        "keyHex": _KEY_HEX, "message": _MESSAGE, "plaintext": _PLAINTEXT})

    expected_hmac = hmac.new(bytes.fromhex(_KEY_HEX), _MESSAGE.encode("utf8"),
                             hashlib.sha256).hexdigest()
    assert out["signatureLength"] == 32, f"HMAC-SHA256 signature was {out['signatureLength']} bytes"
    assert out["signatureHex"] == expected_hmac, (
        f"HMAC-SHA256 signature {out['signatureHex']!r}, expected {expected_hmac!r}")
    assert out["verified"] is True, f"crypto.subtle.verify returned {out['verified']!r}"
    assert out["decrypted"] == _PLAINTEXT, f"AES-GCM round trip returned {out['decrypted']!r}"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(files: dict) -> bytes:
    """A deployment package holding ``files`` (archive path -> source text)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, text in sorted(files.items()):
            zf.writestr(path, textwrap.dedent(text))
    return buf.getvalue()


def _execution_role(ctx, statements) -> dict:
    """A Lambda execution role holding exactly ``statements`` and no logs: grant, so the function
    never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(_teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"),
            "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, timeout=60) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code)}, "Timeout": timeout,
              "MemorySize": 256, "Tags": {"sim2real": CHECK}}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    resp = ctx.client("lambda").invoke(FunctionName=fn, InvocationType="RequestResponse",
                                       Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _invoke_ok(ctx, fn, event=None) -> dict:
    """The payload of one invoke that must not report a FunctionError."""
    err, out = _invoke(ctx, fn, event)
    assert err is None, f"the function failed: {err!r} {out!r}"
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
