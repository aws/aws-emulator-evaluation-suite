"""nodejs-crypto-cipher-round-trip."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "nodejs-crypto-cipher-round-trip"
GROUP = "nodejs-environment"
SERVICES = ['lambda']


_RUNTIME = "nodejs22.x"
_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
_IV_HEX = "cafebabefacedbaddecaf888"
_AAD = "sim2real-aad"
_PLAINTEXT = "lambda gcm round trip"
# AES-256-GCM of _PLAINTEXT under _KEY_HEX, _IV_HEX and _AAD, and PBKDF2-HMAC-SHA256 of "pw" with
# salt "salt", 1000 iterations, 32 bytes: fixed by the algorithms, independent of the runtime.
_CIPHERTEXT_HEX = "e6c2cd44ce1b6f7c25667daf1468e75b2d54b238af"
_TAG_HEX = "4399b18194ebdd6aadb73f1b8d594689"
_PBKDF2_HEX = "0a38253555ce37f5c72a6b703f996814ebf241f203af146e93dcdeb031c5567e"
_FILES = {"index.js": """\
const crypto = require("crypto");

exports.handler = async (event) => {
  const key = Buffer.from(event.keyHex, "hex");
  const iv = Buffer.from(event.ivHex, "hex");
  const aad = Buffer.from(event.aad, "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(event.plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const back = Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  let tampered;
  try {
    const bad = crypto.createDecipheriv("aes-256-gcm", key, iv);
    bad.setAAD(aad);
    const flipped = Buffer.from(tag);
    flipped[0] ^= 1;
    bad.setAuthTag(flipped);
    Buffer.concat([bad.update(ct), bad.final()]);
    tampered = { rejected: false };
  } catch (e) {
    tampered = { rejected: true, message: e.message };
  }
  return {
    ciphertextHex: ct.toString("hex"), tagHex: tag.toString("hex"), decrypted: back, tampered,
    pbkdf2Hex: crypto.pbkdf2Sync("pw", "salt", 1000, 32, "sha256").toString("hex"),
  };
};
"""}



@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """node:crypto in a Node.js function produces the standard AES-256-GCM ciphertext and auth tag,
    decrypts them back, refuses a tampered tag, and derives the standard PBKDF2-SHA256 key.

    Reference: https://nodejs.org/docs/latest-v22.x/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options
    """
    role = _execution_role(ctx, [])
    fn = _function(ctx, role["arn"], _FILES)
    out = _invoke_ok(ctx, fn["name"], {
        "keyHex": _KEY_HEX, "ivHex": _IV_HEX, "aad": _AAD, "plaintext": _PLAINTEXT})
    assert out["ciphertextHex"] == _CIPHERTEXT_HEX, f"AES-256-GCM ciphertext {out['ciphertextHex']!r}"
    assert out["tagHex"] == _TAG_HEX, f"AES-256-GCM auth tag {out['tagHex']!r}, expected {_TAG_HEX!r}"
    assert out["decrypted"] == _PLAINTEXT, f"createDecipheriv returned {out['decrypted']!r}"
    assert out["tampered"]["rejected"] is True, f"a flipped auth tag decrypted: {out['tampered']!r}"
    assert out["pbkdf2Hex"] == _PBKDF2_HEX, f"pbkdf2Sync derived {out['pbkdf2Hex']!r}, expected {_PBKDF2_HEX!r}"



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
