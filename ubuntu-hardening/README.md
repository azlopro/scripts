# Ubuntu server hardening bundle

Target assessed on 2026-09-11:

- Ubuntu Server 26.04.1 LTS;
- server `n0`, reserved IPv4 `192.168.1.74` on `enp2s0`;
- management workstation reserved IPv4 `192.168.1.169`;
- SSH administrator `nibba` with an existing ED25519 key;
- physical console recovery available.

This bundle repairs boot-time DHCP, applies a conservative host baseline,
hides SSH behind fwknop Single Packet Authorization (SPA), and requires an SSH
key plus TOTP. It also produces timestamped, hashed audit evidence.

It does **not** certify an organization to ISO/IEC 27001 and does not claim
CIS Benchmark conformance. See `CONTROL-NOTES.md` for the remaining ISMS work.

## Safety model

- Scripts make no changes unless passed `--apply` or another explicit action.
- Networking, firewall, and SSH cutovers create timestamped backups.
- Each access-sensitive cutover starts a systemd rollback timer first.
- Confirm only from the original session after a completely new session works.
- Never close the original SSH session during a cutover.
- Physical console access is still the final recovery path.

The existing repository-level `startup.sh` is unrelated and is not modified or
called by this bundle.

## 1. Configure and install the bundle

On the management workstation:

```bash
cd ubuntu-hardening
cp hardening.conf.example hardening.conf
chmod 600 hardening.conf
```

Review every value. Set `ACK_DHCP_RESERVATIONS="yes"` because both reservations
have been confirmed. The current root disk is unencrypted: either reinstall
with LUKS now, or set `ACK_UNENCRYPTED_ROOT="yes"` and record that risk in the
ISMS risk register.

Copy the directory while SSH is still unrestricted:

```bash
scp -r ../ubuntu-hardening nibba@192.168.1.74:/tmp/
ssh nibba@192.168.1.74
sudo install -d -o root -g root -m 0755 /opt/company-hardening
sudo cp -a /tmp/ubuntu-hardening/. /opt/company-hardening/
sudo chown -R root:root /opt/company-hardening
sudo chmod 0600 /opt/company-hardening/hardening.conf
```

Run all server commands from `/opt/company-hardening`.

## 2. Capture the initial audit

```bash
sudo ./00-audit.sh
```

Reports are mode-0600 beneath `/var/log/company-hardening/` and contain system
details. Export them only to approved evidence storage.

## 3. Repair boot networking

Keep the current SSH session open:

```bash
sudo ./10-network.sh --apply
```

Open a separate terminal and verify a new key-based connection. Then cancel
the five-minute rollback from the original session:

```bash
sudo ./10-network.sh --confirm
```

Reboot and verify that `192.168.1.74` returns without manually running
`dhcpcd`. Do not continue until this works.

## 4. Apply the non-access baseline

After deciding the disk-encryption exception in `hardening.conf`:

```bash
sudo ./20-base-hardening.sh --apply
```

The optional service and `lxd` group removals remain disabled unless explicitly
selected in the configuration.

## 5. Prepare SPA without closing SSH

```bash
sudo ./30-firewall-spa.sh --prepare
```

This creates `/home/nibba/fwknop-n0.conf`. It contains encryption and HMAC
keys and must be handled as a secret. Copy it to the management workstation:

```bash
scp nibba@192.168.1.74:fwknop-n0.conf ./fwknop-n0.conf
chmod 600 ./fwknop-n0.conf
sudo apt-get install fwknop-client
./client/install-fwknop-client.sh ./fwknop-n0.conf
```

Set `ACK_SPA_CLIENT_COPIED="yes"` using
`sudoedit /opt/company-hardening/hardening.conf`, then keep the existing SSH
session open and enable the gate:

```bash
sudo ./30-firewall-spa.sh --apply
```

From a new management-workstation terminal:

```bash
fwknop -n n0
ssh -o ControlMaster=no -o ControlPath=none nibba@192.168.1.74
```

If it works, confirm from the original session:

```bash
sudo ./30-firewall-spa.sh --confirm
```

Delete the exported `fwknop-n0.conf` from the server and the temporary source
on the workstation after confirming `~/.fwknoprc` is protected with mode 0600.

## 6. Enroll and require TOTP

Install the PAM module without changing SSH:

```bash
sudo ./40-ssh-totp.sh --prepare
./40-ssh-totp.sh --enroll
```

Scan the QR code and store the emergency codes in the approved password or
secrets manager. Do not paste or log the QR seed. Chrony must report a healthy
clock before the next step. For the enrollment prompts, use time-based tokens,
disallow reuse, keep the normal narrow time window unless the phone clock is
known to drift, and enable rate limiting.

Keep the original session open and apply key-plus-TOTP authentication:

```bash
sudo ./40-ssh-totp.sh --apply
```

From a completely new terminal, authorize with SPA and test SSH:

```bash
fwknop -n n0
ssh -o ControlMaster=no -o ControlPath=none nibba@192.168.1.74
```

The login must require the ED25519 key and then a TOTP code, not the Linux
password. Confirm only after this succeeds:

```bash
sudo ./40-ssh-totp.sh --confirm
```

## 7. Seal and verify

Create the file-integrity baseline only after all intended configuration and
application installation is complete:

```bash
sudo ./50-integrity-baseline.sh --apply
sudo ./60-verify.sh
sudo ./00-audit.sh
```

Export AIDE data and the evidence directories to protected off-server storage.
A local integrity database alone cannot resist an attacker with root access.

## Recovery

To inspect timers:

```bash
systemctl list-timers 'company-*-rollback.timer'
```

Timed rollback scripts are stored inside the applicable directory under
`/var/backups/company-hardening/`. From the physical console, run the latest
relevant `rollback-network.sh`, `rollback-access.sh`, or `rollback-ssh.sh` as
root. Access rollback deliberately disables UFW so SSH becomes reachable again;
reapply and retest hardening afterward.

UFW rebuilds its chains when it reloads. After any intentional UFW rule change
or reload, restore the SPA chain ordering and verify it:

```bash
sudo ufw reload
sudo systemctl restart fwknop-server.service
sudo ./30-firewall-spa.sh --status
```

## Operational follow-up

Before hosting company workloads, define and test:

- approved application ports and service-specific AppArmor profiles;
- encrypted off-site backups and restoration exercises;
- remote TLS-protected logging and retention;
- patch/reboot ownership and maintenance windows;
- a second named administrator and emergency-access process;
- quarterly access, firewall, AIDE, and configuration-drift reviews.
