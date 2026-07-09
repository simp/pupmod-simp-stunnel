# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`simp-stunnel` is a SIMP Puppet module that manages [stunnel](https://www.stunnel.org),
the TLS wrapper daemon, with SIMP PKI integration. It installs the `stunnel`
package, provisions the `stunnel` service account, lays down TLS certificates
(optionally via SIMP's `pki` module), and generates stunnel configuration plus
the matching systemd units for each tunnel you define.

The module supports **two deployment models**:

- **Monolithic mode** — a single system-wide `stunnel` daemon reading one
  `/etc/stunnel/stunnel.conf`, where each tunnel is a `concat::fragment`
  appended by a `stunnel::connection` define. This is the older model.
  Managed by `stunnel::config` + `stunnel::service`, gated behind the private
  `stunnel::monolithic` class (`manifests/monolithic.pp`).
- **Instance mode** — one independent systemd service **per tunnel**, each with
  its own config file and (optionally) its own chroot. Managed by the
  `stunnel::instance` define (`manifests/instance.pp`), which writes
  `/etc/stunnel/stunnel_managed_by_puppet_<name>.conf` and spawns
  `stunnel_managed_by_puppet_<name>.service`. This is the modern model and the
  one to prefer for new tunnels.

`stunnel::instance_purge` (backed by the custom `stunnel_instance_purge` native
type) tears down instance config files and services that Puppet no longer
manages, so removing a tunnel from your manifest actually stops and cleans it up.
It is included by default from `init.pp` (`manifests/init.pp:99-101`).

### Business logic

The main class is a thin composition root. `stunnel` (`manifests/init.pp:80-102`)
is the only public class you `include`; it `contain`s `stunnel::install` and,
when `$purge_instance_resources` is true (the default), includes
`stunnel::instance_purge`. It does **not** itself set up any tunnel — the
`stunnel::connection` and `stunnel::instance` defines do that.

- **`stunnel` (`manifests/init.pp:80-102`)** — public entry class. Holds the
  shared PKI parameters (`$app_pki_dir` defaults to
  `/etc/pki/simp_apps/stunnel/x509`, `init.pp:81`), the service account
  identity (`$setuid`/`$setgid` = `stunnel`, `$uid`/`$gid` = `600`,
  `init.pp:87-90`), and the `simp_options` feature toggles (see the seam
  section). `$purge_instance_resources` defaults to `true` (`init.pp:95`).
- **`stunnel::install` (`manifests/install.pp`, private)** — `assert_private()`
  at `install.pp:16`. Installs the `stunnel` package, creates `/etc/stunnel`,
  and conditionally `include`s `haveged` when `$stunnel::haveged` is set
  (`install.pp:18`).
- **`stunnel::config` (`manifests/config.pp`)** — the monolithic daemon's global
  config. Inherits `stunnel`, `include`s `stunnel::monolithic`, ensures the
  `stunnel::account`, optionally runs `pki::copy` (`config.pp:168-173`), builds
  the chroot tree, writes `/etc/stunnel/stunnel.conf` via `concat` +
  `connection_conf.erb`, and installs the `stunnel.service` unit from
  `connection_systemd.erb` (`config.pp:297-299`). Requires a value for
  `$crypto_backend` — see gotchas.
- **`stunnel::service` (`manifests/service.pp`)** — manages the monolithic
  `stunnel` service; removes the legacy SysV init script; **fails the compile on
  non-systemd systems** (`service.pp:18`).
- **`stunnel::monolithic` (`manifests/monolithic.pp`, private)** —
  `assert_private()` at `monolithic.pp:6`. Contains `stunnel::config` and
  `stunnel::service` and wires the notify chain (config `~>` service, and
  `haveged ~> service` when enabled).
- **`stunnel::account` (`manifests/account.pp`, private define)** —
  `assert_private()` at `account.pp:34`. `ensure_resources` the stunnel user and
  group so multiple tunnels sharing one user/group don't collide.
- **`stunnel::connection` (`manifests/connection.pp`, define)** — a tunnel in the
  **monolithic** model: appends a `concat::fragment` to `stunnel.conf`
  (`connection.pp:285-288`) and, for servers, opens the firewall
  (`connection.pp:294-301`) and tcpwrappers (`connection.pp:303-311`).
- **`stunnel::instance` (`manifests/instance.pp`, define)** — a tunnel in the
  **instance** model: its own conf file, chroot, `pki::copy`, systemd unit, and
  service (`instance.pp:328-496`). **Fails the compile on non-systemd systems**
  (`instance.pp:485`).
- **`stunnel::instance::reserve_port` (`manifests/instance/reserve_port.pp`,
  private define)** — `assert_private()` at `reserve_port.pp:8`. A "canary"
  define declared once per accept-port by both `connection` and `instance`
  (`connection.pp:243`, `instance.pp:283`); a duplicate-declaration error here
  is the intended signal that two tunnels want the same listen port.
- **`stunnel::instance_purge` (`manifests/instance_purge.pp`)** — declares the
  `stunnel_instance_purge` native resource over `/etc/stunnel`,
  `/etc/rc.d/init.d`, `/etc/systemd/system` (`instance_purge.pp:15-24`).

## Gotchas / non-obvious details

- **`$crypto_backend` has no default and is version-dependent.**
  `stunnel::config` declares `Enum['engine','none'] $crypto_backend` with **no
  default** (`config.pp:149`); `stunnel::instance` reads
  `stunnel::config::crypto_backend` via `simplib::lookup` defaulting to `'none'`
  (`instance.pp:281`). The value is supplied from module data by OS: `'engine'`
  for RedHat-8/RedHat-9 (`data/os/RedHat-8.yaml`, `data/os/RedHat-9.yaml`),
  `'none'` in `data/common.yaml`. Per the docstring, engine options only exist
  on EL9 and earlier; EL10 dropped the engine option, hence `'none'` there
  (`config.pp:116-119`).
- **systemd is mandatory.** Both `stunnel::service` (`service.pp:18`) and
  `stunnel::instance` (`instance.pp:485`), and the monolithic PID handling in
  `config.pp:179-190`, call `fail(...)` when `systemd` is not in
  `$facts['init_systems']`. There is no SysV path anymore — the module actively
  removes the old init script (`service.pp:7`).
- **The chroot is skipped when SELinux is enabled — but the two defines differ.**
  In `stunnel::config`, a chroot is used **unless** SELinux is enforcing/permissive
  (`config.pp:161-166`). In `stunnel::instance` it is the opposite polarity: a
  default `/var/stunnel_<name>` chroot is only chosen when SELinux is **disabled**
  (`instance.pp:313-318`). Read those blocks carefully before touching chroot
  logic. Either way, `$chroot` may never be `/` or under `/var/run`
  (`config.pp:206-212`, `instance.pp:345-351`).
- **`reserve_port` is a deliberate compile-time port-collision detector.** Both
  tunnel defines declare `stunnel::instance::reserve_port { $_dport: }` keyed on
  the accept port. Two tunnels on the same port produce a duplicate-resource
  error on purpose (`reserve_port.pp:1-9`). Don't "fix" that by making the name
  unique.
- **The purge type stops/removes *unmanaged* stunnel services.** The
  `stunnel_instance_purge` provider searches the system for services matching the
  resource name prefix, subtracts the ones in the catalog, and stops/disables +
  deletes files for the remainder
  (`lib/puppet/provider/stunnel_instance_purge/purge.rb:15-84`). The type's
  `autobefore(:service)` (`lib/puppet/type/stunnel_instance_purge.rb:50-57`)
  matches any service starting with `stunnel` **or** the namevar, so the purge
  always runs before those services start — this is what prevents port conflicts
  when a tunnel is renamed. Its docstring warns in caps that the namevar must be
  precise (`stunnel_instance_purge.rb:26`); a loose prefix could purge unrelated
  services.
- **Instances created before module 6.3.0 are not auto-removed.** The
  `instance.pp` header (`instance.pp:30-31`) notes there was no safe way to clean
  up pre-6.3.0 files, so those must be removed by hand.
- **FIPS narrows the allowed `ssl_version` set.** When FIPS is on, only
  `TLSv1`/`TLSv1.1`/`TLSv1.2` validate; when off, `all`/`SSLv2`/`SSLv3` are also
  allowed (`connection.pp:248-255`, `instance.pp:290-297`). FIPS is **not**
  enabled by default — the comment explains this is to keep TLS1.2 usable
  (`config.pp:96-97`, `instance.pp:134-135`).
- **`haveged` defaults differ between the two models.** `stunnel::instance`
  defaults `$haveged` to `simp_options::haveged` **falling back to `true`**
  (`instance.pp:215`), whereas the main class `stunnel::haveged` falls back to
  `false` (`init.pp:93`). So an instance pulls in `haveged` by default unless
  `simp_options::haveged` says otherwise.
- **`tcpwrappers::allow` pins `pattern => 'ALL'`** in both defines to work around
  a bug in the EL7.9 stunnel build (`connection.pp:308-309`,
  `instance.pp:472-475`).
- **`simp/simp_options` is NOT a declared dependency** in `metadata.json`, yet
  the manifests consume the `simp_options::*` seam via `simplib::lookup` /
  `simplib::dlookup` (both provided by `simp/simplib`). Route SIMP feature
  toggles through that seam rather than assuming `simp_options` is included.
- **Docstring note:** `manifests/init.pp` documents `@param pki` twice
  (`init.pp:3-14` and `init.pp:70-71`) — harmless duplication in the
  puppet-strings header, left as-is.

## The `simp_options` / `dlookup` seam

This module's real business-logic seam is the two-layer override system. The
main class reads plain `simplib::lookup('simp_options::*', ...)` toggles
(`manifests/init.pp`):

| Line | Key | `default_value` |
|------|-----|-----------------|
| `init.pp:82` | `simp_options::pki::source` | `'/etc/pki/simp/x509'` |
| `init.pp:91` | `simp_options::syslog` | `false` |
| `init.pp:92` | `simp_options::fips` | `pick($facts['fips_enabled'], false)` |
| `init.pp:93` | `simp_options::haveged` | `false` |
| `init.pp:94` | `simp_options::pki` | `false` |

The `stunnel::connection` and `stunnel::instance` defines add a second layer via
`simplib::dlookup`, giving each parameter a **per-instance → global → simp_options
default** fallback chain. The pattern (from `connection.pp:237-239` /
`instance.pp:213-267`) is:

```puppet
# per-instance override, then a simp_options default:
$trusted_nets = pick(
  simplib::dlookup('stunnel::connection', 'trusted_nets', $name, { 'default_value' => undef }),
  simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] })
)
```

`simplib::dlookup('stunnel::connection', 'param', $name, ...)` resolves a global
override (`stunnel::connection::param: ...` in Hiera, affecting all instances)
**or** an instance-specific override
(`Stunnel::Connection[rsync]::param: ...`), falling back to the given default —
often another `simp_options::*` lookup. Keep new per-tunnel parameters on this
`dlookup` seam so both override styles keep working (see the header docs at
`connection.pp:1-16` and `instance.pp:1-16`).

## Dependencies

Module dependencies (from `metadata.json`) — **all required; there is no
`simp.optional_dependencies` block and no `assert_optional_dependency` call
anywhere in this module:**

- `puppetlabs/concat` `>= 6.4.0 < 10.0.0` — the monolithic `stunnel.conf` is
  assembled with `concat` / `concat::fragment`.
- `puppetlabs/stdlib` `>= 8.0.0 < 10.0.0` — `ensure_resource(s)`, `dirname`,
  `regsubst`, etc.
- `simp/haveged` `>= 0.4.5 < 1.0.0` — entropy daemon, `include`d when `$haveged`.
- `simp/iptables` `>= 6.5.3 < 8.0.0` — `iptables::listen::tcp_stateful` for
  server-side firewall rules.
- `simp/pki` `>= 6.2.0 < 7.0.0` — `pki::copy` for certificate provisioning.
- `simp/simplib` `>= 4.9.0 < 5.0.0` — `simplib::lookup`, `simplib::dlookup`,
  `simplib::validate_array_member`, the `Simplib::*` types, and the
  `fips_enabled` fact.
- `simp/tcpwrappers` `>= 6.2.0 < 7.0.0` — `tcpwrappers::allow` for server-side
  access control.

There are **no optional dependencies.** `simp/haveged`, `simp/iptables`,
`simp/pki`, and `simp/tcpwrappers` are hard runtime dependencies even though the
manifests only `include` them conditionally.

Runtime requirement (from `metadata.json` `requirements`): `puppet
>= 7.0.0 < 9.0.0`. This is the **older** SIMP baseline — the module has **not**
yet migrated to OpenVox. The `Gemfile` still installs the upstream Puppet gem
only, via `gem 'puppet', puppet_version` with `puppet_version` defaulting to
`['>= 7', '< 9']` (`Gemfile:23,29`). When the baseline moves this module to
OpenVox, update both `metadata.json` and this line.

Supported OS matrix (from `metadata.json`): CentOS 9/10; RedHat 8/9/10;
OracleLinux 8/9/10; Rocky 8/9/10; AlmaLinux 8/9/10.

## Repository layout

- `manifests/init.pp` — public `stunnel` class (composition root).
- `manifests/install.pp` — private; package + `/etc/stunnel`.
- `manifests/config.pp` — monolithic global config, chroot, `stunnel.conf`.
- `manifests/service.pp` — monolithic systemd service.
- `manifests/monolithic.pp` — private; contains config + service.
- `manifests/account.pp` — private define; stunnel user/group.
- `manifests/connection.pp` — define; a tunnel in monolithic mode.
- `manifests/instance.pp` — define; a tunnel as its own systemd instance.
- `manifests/instance/reserve_port.pp` — private "canary" define for port
  collision detection.
- `manifests/instance_purge.pp` — declares the purge resource (included by
  default).
- `types/connect.pp` — `Stunnel::Connect` data type (`connect` target values).
- `types/ocspflags.pp` — `Stunnel::OcspFlags` data type (allowed OCSP flags).
- `lib/puppet/type/stunnel_instance_purge.rb` — custom native type; `autobefore`
  ordering against services.
- `lib/puppet/provider/stunnel_instance_purge/purge.rb` — provider that stops,
  disables, and deletes unmanaged stunnel instances.
- `templates/connection_conf.erb`, `templates/connection_systemd.erb` —
  monolithic conf fragment + systemd unit.
- `templates/instance_conf.erb`, `templates/instance_systemd.erb` — per-instance
  conf + systemd unit.
- `data/common.yaml` — `stunnel::config::crypto_backend: 'none'`.
- `data/os/RedHat-8.yaml`, `data/os/RedHat-9.yaml` — override
  `crypto_backend` to `'engine'`.
- `hiera.yaml` — module data hierarchy (v5): OS name+major → OS → OS family+major
  → OS family → common.
- `metadata.json` — deps, OS matrix, Puppet requirement.
- `spec/classes/`, `spec/defines/`, `spec/unit/` — rspec-puppet + Ruby unit
  tests.
- `spec/acceptance/suites/default/` — beaker suites: `00_instances_spec.rb`,
  `01_connection_spec.rb`, `20_connectivity_spec.rb`; nodesets under
  `spec/acceptance/nodesets/` (14 nodesets).
- `REFERENCE.md` — generated Puppet Strings reference.

### CI (`.github/workflows/pr_tests.yml`)

Six standard baseline jobs run on `ubuntu-latest`:

- `puppet-syntax` — `bundle exec rake syntax`
- `puppet-style` — `bundle exec rake lint` + `metadata_lint`
- `ruby-style` — `bundle exec rake rubocop` (`continue-on-error: true`)
- `file-checks` — `rake check:dot_underscore` + `check:test_file`
- `releng-checks` — version/tag/changelog checks + `pdk build --force`
- `spec-tests` — `bundle exec rake spec` on Puppet 8.x / Ruby 3.2

Plus an **active `acceptance` job** (not just a placeholder): it provisions
libvirt/Vagrant and runs `bundle exec rake beaker:suites[default,<node>]` under
`BEAKER_HYPERVISOR: 'vagrant_libvirt'` (workflow line ~153), matrixed over
`almalinux8` and `almalinux10` (lines ~132-133).

## Common commands

```sh
# Install dependencies
bundle install

# Run all unit tests
bundle exec rake spec

# Run one spec file
bundle exec rspec spec/defines/instance_spec.rb

# Puppet lint / syntax
bundle exec rake lint
bundle exec rake syntax

# Ruby lint (native type/provider)
bundle exec rake rubocop

# Regenerate REFERENCE.md from puppet-strings docstrings
puppet strings generate --format markdown --out REFERENCE.md

# Run a beaker acceptance suite on a given nodeset
bundle exec rake beaker:suites[default,almalinux8]
```

Relevant gem pins (from `Gemfile`): `rubocop ~> 1.88.0` (`Gemfile:16`),
`puppetlabs_spec_helper ~> 8.0.0` (`Gemfile:30`), `simp-rake-helpers ~> 5.24.0`
(`Gemfile:36`), `simp-beaker-helpers ~> 2.0.0` (`Gemfile:53`). The spec harness
requires `puppetlabs_spec_helper/module_spec_helper` (`spec/spec_helper.rb:11`).
The tested Puppet range is `>= 7 < 9`.

## Conventions

- Preserve the `@summary` / `@param` puppet-strings docstrings — they drive
  `REFERENCE.md`. Regenerate `REFERENCE.md` after changing docs or parameters.
- Keep new per-tunnel parameters on the `simplib::dlookup('stunnel::connection'|
  'stunnel::instance', 'param', $name, { 'default_value' => ... })` seam so both
  global and instance-specific Hiera overrides keep working.
- Route SIMP feature toggles through `simplib::lookup('simp_options::*', {
  'default_value' => ... })` with an explicit default rather than assuming
  `simp_options` is included.
- Keep OS-specific values (`crypto_backend`) in `data/*.yaml`, not hard-coded in
  manifests.
- Mark internal classes/defines `assert_private()` as the existing ones do
  (`account.pp:34`, `monolithic.pp:6`, `install.pp:16`,
  `instance/reserve_port.pp:8`).
- Preserve the `reserve_port` port-collision guard — it is intentional.
- `Gemfile`, `spec/spec_helper.rb`, and `.github/workflows/pr_tests.yml` carry a
  **puppetsync** notice — they are baseline-managed and the next sync overwrites
  local edits. Push changes to those files upstream to the baseline, not here.
- Match the existing 2-space Puppet indentation and aligned-arrow / aligned-`=`
  parameter style used across `manifests/`.
