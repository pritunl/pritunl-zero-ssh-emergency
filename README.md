# pritunl-zero: emergency ssh client

This client can be used to create SSH certificates without a Pritunl Zero
server. Use only when the Pritunl Zero server is inaccessible and SSH access
is needed.

## Preparation

This must be done before losing access to the Pritunl Zero server. Keys are encrypted with AES-256.

```bash
# Export SSH authorities
sudo pritunl-zero export-ssh ~/ssh_backup.json
```

## Usage

Certificates are valid for 30 minutes.

```bash
# Install emergency ssh client
go get github.com/pritunl/pritunl-zero-ssh-emergency

# Create SSH certificate
~/go/bin/pritunl-zero-ssh-emergency ~/ssh_backup.json ~/.ssh/id_rsa.pub
ssh-keygen -L -f ~/.ssh/id_rsa-cert.pub
```

## Custom roles

By default only the `emergency` role is added to the certificate principals.
Custom roles can be appended to the command arguments as shown in the example
below.

```bash
# Custom roles
~/go/bin/pritunl-zero-ssh-emergency ~/ssh_backup.json ~/.ssh/id_rsa.pub role1 role2
```

## Strict host checking

If your SSH configuration has strict host checking enabled you may need to
remove the option from the SSH configuration to connect. This can be done with
the pritunl-ssh client by running the command `pritunl-ssh clear-strict-host`.
The bastion host configuration can be removed with the command
`pritunl-ssh clear-bastion-host`. The command `pritunl-ssh clear` will remove
all SSH configuration changes made.

## License

Please refer to the [`LICENSE`](LICENSE) file for a copy of the license.
