## Tutorial 1 — Setting up an identity

**Scenario:** Alice Nguyen is a researcher at Oak Ridge National Laboratory.
She needs a `certified` identity so she can authenticate to internal APIs
and eventually connect with collaborators at other institutions.

### 1. Create your identity

```bash
certified init 'Alice Nguyen' \
    --email alice.nguyen@ornl.gov \
    --config $HOME/etc/certified
```

This creates a config directory with a CA key, an identity cert, and
self-trust entries so Alice can immediately call her own services.
See [Create an identity](../howto/init.md) for all available options.

### 2. Inspect what was created

```bash
ls $HOME/etc/certified/
# CA.key  CA.crt  id.key  id.crt  known_servers/  known_clients/
```

Export the identity cert in base64-DER (for sharing with a signer):

```bash
certified get-ident --config $HOME/etc/certified
```

### 3. Run a quick self-test

Start a minimal echo server using your new identity:

```bash
certified serve --config $HOME/etc/certified examples.echo:app https://127.0.0.1:8443
```

Then call it from another terminal:

```bash
certified message --config $HOME/etc/certified https://127.0.0.1:8443/echo/hello
```

If the server responds, your certificate stack is working end-to-end.
