"""connection-password-hidden-when-requested."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connection-password-hidden-when-requested"
GROUP = 'connection'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """get_connection(HidePassword=True) must not return the plaintext PASSWORD property."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-conn-")
    glue.create_connection(
        ConnectionInput={
            "Name": name,
            "ConnectionType": "JDBC",
            "ConnectionProperties": {
                "JDBC_CONNECTION_URL": "jdbc:mysql://example.com:3306/db",
                "USERNAME": "admin",
                "PASSWORD": "super-secret-password",
            },
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_connection(ConnectionName=name))

    plain_resp = glue.get_connection(Name=name)
    plain_props = plain_resp["Connection"]["ConnectionProperties"]
    assert plain_props.get("PASSWORD") == "super-secret-password", (
        "sanity check: default get_connection should return the stored password"
    )

    hidden_resp = glue.get_connection(Name=name, HidePassword=True)
    hidden_props = hidden_resp["Connection"]["ConnectionProperties"]
    assert "PASSWORD" not in hidden_props, (
        "HidePassword=True must omit the PASSWORD property entirely, got "
        f"{hidden_props.get('PASSWORD')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
