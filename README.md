# pritunl-zero: emergency ssh client

This client can be used to create SSH certificates without a Pritunl Zero
server. Use only when the Pritunl Zero server is inaccessible and SSH access
is needed.

## Preparation

This must be done before losing access to the Pritunl Zero server. Use a long
encryption passphrase.

```bash
# Export SSH authorities
sudo pritunl-zero export-ssh ~/ssh_backup.json
```

## Usage

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

## License

Please refer to the [`LICENSE`](LICENSE) file for a copy of the license.
