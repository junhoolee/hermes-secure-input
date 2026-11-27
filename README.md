# hermes-secure-input

`secure-input` is a [Hermes Agent](https://hermes-agent.nousresearch.com/) plugin that lets you give Hermes a credential without the value ever passing through Slack.
A credential here means one of four things: an API key, a website login (username and password), a password that a script on the Mac running Hermes reads from the macOS Keychain, or a one-time code that a website asks for in the middle of a login.

How it works:

- The Slack conversation receives a message that describes the request and has an "입력 페이지 열기" (open input page) link button. The value itself never goes to Slack.
- The link opens an input page that the computer running Hermes starts for that one request only.
- You type the value into that page. The browser encrypts it and sends it straight to the computer running Hermes.
- That computer decrypts the value and saves it where you chose. The Slack message is then replaced by a result line such as "saved".

> **Language: the user interface is Korean only.**
> The input page, the Slack messages, the `!secure-input` command replies and the notes the agent receives are all written in Korean. There is no English version yet.
> This README quotes the Korean text you will see with an English translation (in parentheses, or to the right of each line in the sample messages), so you can match what is on screen.

> **Platform: tested only on macOS, with Hermes Agent v0.23.3.** The Keychain store works only on macOS. The plugin also needs [Tailscale](https://tailscale.com/). See [Requirements](#requirements).

## Why not just paste it into Slack

A value you type into a chat message passes through Slack's servers.
By default Slack keeps messages for the lifetime of the workspace ([Slack help](https://slack.com/help/articles/115005393586-Edit-message-retention-settings-for-specific-conversations): "By default, Slack will retain all messages for the lifetime of your workspace").
A value typed into a Slack modal (an input dialog opened by a Slack app) also passes through Slack's servers, and Slack's own documentation says not to ask for passwords in modals ([Slack modals documentation](https://docs.slack.dev/surfaces/modals/), "Don't prompt for login information").
Hermes itself asks for login one-time codes through a Slack button that opens such a modal.
This plugin therefore takes values on a separate page instead of in Slack.

## What you can enter and where it is stored

Two terms first:

- **Profile**: an independent workspace inside Hermes. Each profile has its own configuration, `.env` file and vault. The `default` profile's folder is `~/.hermes`; any other profile's folder is `~/.hermes/profiles/<profile name>`.
- **Store**: a place a value is saved to. There are three. The Korean label each store has on the input page is in quotes.
  - `.env` ("설정 파일(.env)"): the environment-variable file in the profile's folder. Values are not encrypted.
  - vault ("Hermes 암호화 저장소(vault)"): Hermes's encrypted store, one per profile. Hermes uses the logins saved here to fill in login forms in its browser.
  - macOS Keychain ("Mac 키체인"): the macOS password store. The plugin writes to the default keychain of the macOS user account that runs Hermes (normally its login keychain), using macOS's `/usr/bin/security` command. The Keychain is the same for every profile.

| What you enter | Stores you can choose | Store selected at first |
|---|---|---|
| API key | `.env`, macOS Keychain. You may select both. | `.env` |
| Website login (username type, username, password, and optionally an authenticator setup key) | vault only | vault |
| Keychain password (a password a script on this Mac reads from the Keychain) | macOS Keychain only | macOS Keychain |
| One-time code during a login | none. It is never stored. | none |

How each store keeps the value:

- `.env`: one `NAME=value` line in the chosen profile's `.env`. If a line for the same variable exists, that line is replaced. Other lines are not touched. If saving fails, the file is left exactly as it was.
- vault: a login item for that site's address in the chosen profile's vault. If an item already exists for the same site address and the same username, the new item is saved and then the old one is deleted, together with the old item's authenticator setup key. So a setup key saved before is lost unless you enter it again. Items saved under a different username stay.
- macOS Keychain: one Keychain item, found by two names, `service` and `account`. How those names are chosen is in [Keychain item names](#keychain-item-names). If an item with those names exists, its value is replaced and the old value cannot be recovered.
- One-time code: Hermes types it once into the code field of the login page it is working on, then discards it.

API keys and Keychain passwords may contain only characters you can type on a US keyboard (ASCII letters, digits, symbols and spaces). An API key may be up to 4,096 characters. Any value going into the Keychain (a Keychain password, or an API key with the Keychain store selected) must be at most 1,024 characters and must not start or end with a space. A website login password may contain any characters except line breaks and control characters, up to 1,024 characters, and is saved exactly as typed, including spaces at the start or end.

You do not need to create or unlock a vault first. If the profile has no vault yet, Hermes creates the vault file and its key when the first login is saved.

You choose the username type on the input page with one of three buttons: "이메일" (email), "사용자 이름" (user name), "전화번호" (phone number).
The choice changes the label and example of the username field and is saved with the vault item. Hermes fills login forms the same way whichever type you pick.
An authenticator app is a phone app that makes time-based login codes (TOTP). The authenticator setup key is the text key a site shows when you add your account to such an app.
If you save the setup key with the login, Hermes generates the code itself when that site later asks for one during a login, and no input page is opened.

### Keychain passwords

Use a Keychain password request for a password that a script on this Mac reads from the Keychain with the `security` command, for example a backup script's password.
The value is saved to the macOS Keychain only.
On the input page you type the password twice, once in each of two fields; the two must match before you can send.
The value rules are the Keychain rules above.
In the Slack message and on the input page this request type is called "비밀번호" (password).
You do not choose a profile on the input page. The "로그를 남길 프로필" (profile to log to) shown in the Slack message is the profile whose [audit log](#audit-log) records the request. It is the profile of the conversation the request came from, unless the agent set another one with the tool argument `target_profile`.

### Keychain item names

The agent or the command passes only one name, `keychain_item`. The plugin turns that name into the actual Keychain item:

- **A name on the Keychain allow list.** The allow list is the setting `keychain_items`, where you list Keychain items the plugin may write to, normally items a script already reads (see [Letting the plugin write to an existing Keychain item](#letting-the-plugin-write-to-an-existing-keychain-item-keychain_items)). If the name equals an entry's `id`, the plugin writes to the existing item with that entry's `service` and `account`. Allow-list entries can only be used by Keychain password requests; if the agent passes an allow-list `id` for an API key, the tool refuses the request.
- **Any other name.** The plugin uses its own item: `service` is `hermes-secure-input.<name>` and `account` is `hermes-secure-input`. The name must be 1 to 40 characters of lowercase letters, digits and `-`, starting with a lowercase letter or a digit.
- If such a plugin-owned item does not exist yet, the input page says "새 항목입니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 값을 보낸 뒤 그 프로그램의 설정에서 직접 확인하세요." (This is a new item. After sending, check in the reading program's own settings that it reads this item name and Keychain account name.) The agent's result carries a different note: no program reads this item yet, the user has to check that in the program's settings, and the agent should tell the user the item name and account name and must not read the item's value. Changing a script to read the new item is up to you.
- When an API key is saved to the Keychain and the agent passes no name (the `!secure-input key` command never does), the name is the variable name in lowercase with `_` changed to `-`. For example, `EXA_API_KEY` is saved under the service `hermes-secure-input.exa-api-key`. If that name breaks the name rules above (for example, a variable starting with `_` or longer than 40 characters) or is already used by an allow-list entry, the Keychain store cannot be used for that key unless the agent passes a name of its own. The `!secure-input key` command cannot pass one, so save such a key to `.env`.

### Which stores are selected in advance

The "저장 위치" (stores) list on the input page shows one row for each store that the request type can use.

- When the agent makes a request it may choose which stores to select and give a reason for each. Those stores start selected, and each reason is shown as a quotation under "AI 모델이 이 저장 위치에 적은 이유" (the reason the AI model gave for this store). The Slack message shows it too, in a line such as `Hermes가 적은 이유(Mac 키체인): "..."` (reason Hermes gave (macOS Keychain)). Double quotes (`"`) inside a reason are shown as single quotes (`'`), so a reason cannot close the quotation and continue as if the plugin were speaking.
- In the Slack message only the title is bold. Reasons, the purpose text, the label, and the allow list's `label` and `used_by` are sent as unformatted text (Block Kit `plain_text`). According to Slack's documentation, Slack then shows that text exactly as written: `*bold*`, `_italic_`, `~strike~`, `` `code` ``, emoji names such as `:smile:`, addresses and mentions such as `<!channel>` are not turned into formatting, emoji images, links or mentions. The result message (which contains the label) works the same way. Outside Slack (CLI, the Hermes desktop app, other messengers), and when the plugin falls back to a plain text message because it could not send the Slack button message, the Hermes gateway decides how text looks. The plugin cannot stop formatting there, so the same text may show up formatted or as a link.
- If the agent chooses nothing, the "Store selected at first" column of the table above applies.
- For an API key, whatever the agent chose, every store where a key with that variable name was ever saved successfully also starts selected. This history is shared by all profiles: a past save to the `worker` profile's `.env` also selects `.env` for a request that saves to `default`. This stays so even after you delete that value (see [The copies record](#the-copies-record)). You can still switch it off on the page.
- With an API key you switch each of its two stores on or off yourself. A website login and a Keychain password have only one store each, which cannot be switched off. At least one store must be selected to send.
- If you switch off `.env` for an API key, the page warns: "Hermes는 이 키를 `.env`에서 읽습니다. 끄면 Hermes는 이번에 넣는 키를 쓰지 못하고, `.env`에 이미 값이 있으면 그 값은 바뀌지 않습니다." (Hermes reads this key from `.env`. If you switch it off, Hermes cannot use the key you are entering now, and any value already in `.env` stays unchanged.) To let Hermes use a key kept only in the Keychain, see [Using an API key kept only in the Keychain](#using-an-api-key-kept-only-in-the-keychain).
- You can send anyway after the warning. The agent cannot lock a store on or off.

### Saving to several stores

Only an API key can have more than one store selected. With both selected, the value is written to `.env` first and then to the Keychain.

- Before writing anything, the plugin checks every selected store. If any one of them cannot be written, nothing is written anywhere. The page says "아무 데도 저장하지 않았습니다" (nothing was saved), with the store that cannot be written and why. This does not count as a failed attempt, and your input stays on the page. Fix the cause, or, for an API key, switch that store off, and send again from the same page.
- If one store fails in the middle of writing, the stores already written are not rolled back. The page title is "일부만 저장했습니다" (only partly saved) and it shows, per store, whether it was saved. To fill in the store that failed, ask for a new link and send with that store selected. (If an already-saved store is also selected, it is written again with the value you enter this time.)
- If none of the selected stores could be saved, it counts as one failed attempt and you can send again from the same page.

## Requirements

- **Hermes Agent**: built and tested on v0.23.3. Older versions were not checked; if yours is older, update Hermes first (`hermes update`, see [Updating Hermes](https://hermes-agent.nousresearch.com/docs/getting-started/updating)). `hermes --version` shows the installed version; its first line looks like `Hermes Agent v0.23.3 (2026.9.24) · ...`. The Python packages the plugin needs (a web server and a cryptography library) already come with Hermes, so there is nothing else to install.
- **Operating system**: the computer running Hermes was tested on macOS only. Other systems were not checked. The macOS Keychain store works only on macOS.
- **Tailscale**: a service that joins your devices into one private network, called a tailnet. Follow the [Tailscale quickstart](https://tailscale.com/docs/how-to/quickstart) to install it and add devices. You need all of the following:
  - Tailscale is installed and logged in on the computer running Hermes.
  - The device you type values on (phone or PC) is in the same tailnet with Tailscale switched on. You type values in that device's browser.
  - That device's Tailscale is logged in to the same Tailscale account as the Hermes computer's. How to allow other accounts is in [Which Tailscale accounts can open a link](#which-tailscale-accounts-can-open-a-link).
  - If the device you read Slack on is not in the tailnet, the input page does not open there. Press the same Slack message's button on another device that is in the tailnet with the same account, within 60 seconds of the link being made. A try that did not open the page does not use up the link.
  - MagicDNS (names for tailnet devices) and HTTPS certificates are enabled for the tailnet. Both are switched on in the admin console's [DNS page](https://console.tailscale.com/admin/dns): MagicDNS under its MagicDNS section ([MagicDNS docs](https://tailscale.com/docs/features/magicdns)), HTTPS with "Enable HTTPS" under "HTTPS Certificates" ([Enabling HTTPS docs](https://tailscale.com/docs/how-to/set-up-https-certificates)). Tailscale warns when you enable HTTPS that the names of devices that get certificates are published in a public certificate log. The plugin does not work without HTTPS certificates, so if you cannot accept device names in a public log, you cannot use this plugin.
  - Tailscale Serve is available. Serve makes a web server on this computer reachable over HTTPS, only from devices in the same tailnet. Serve needs HTTPS certificates enabled ([Tailscale Serve docs](https://tailscale.com/docs/features/tailscale-serve)).
  - The plugin looks for the Tailscale command-line tool in this order. If the environment variable `SECURE_INPUT_TAILSCALE_BIN` has a value, that value is used even if no file exists at that path. Otherwise `/Applications/Tailscale.app/Contents/MacOS/Tailscale` is used, and if that does not exist either, `tailscale` from `PATH`. If you installed the macOS app, the app path above is the command-line tool and you do not need to set anything, even if `which tailscale` prints nothing.
  - Only if you need `SECURE_INPUT_TAILSCALE_BIN`: add the line `SECURE_INPUT_TAILSCALE_BIN=<path>` with a text editor to the `.env` of the profile that starts the gateway (use an editor because the plugin itself refuses to save names starting with `SECURE_INPUT_`). In the standard setup the `default` profile starts the gateway, so that is `~/.hermes/.env`. Hermes reads that `.env` into its environment at startup, so restart the gateway after adding the line (`hermes gateway restart`).
- **Slack** (optional): to use the plugin from Slack, the Hermes gateway must be connected to Slack. The gateway is the Hermes process that handles messenger and CLI conversations. The plugin also works in Hermes CLI conversations (see [Starting a request yourself](#starting-a-request-yourself-with-a-command)).
  - `hermes gateway status` shows only whether the gateway is running, not whether Slack is connected. To check Slack, run `grep -E "slack (connected|failed to connect)" ~/.hermes/logs/gateway.log | tail -1` on the Hermes computer. `✓ slack connected` means connected; `✗ slack failed to connect` means it could not connect. If nothing is printed, restart the gateway with `hermes gateway restart` and run the same command again: at startup the gateway tries to connect to Slack if Slack is enabled and writes one of the two lines. If there is still nothing, Slack is not enabled on this gateway.
  - If Slack is not connected or not enabled, follow the [Hermes Slack setup guide](https://hermes-agent.nousresearch.com/docs/user-guide/messaging/slack).
- The input page is committed to the repository already built (`secure_input/static/`). You do not need Node.js just to use the plugin.

Check Tailscale on the Hermes computer before installing, with the two commands below. Neither changes any setting. If you installed the macOS app and have no `tailscale` command, use `/Applications/Tailscale.app/Contents/MacOS/Tailscale` instead of `tailscale` here and in every other `tailscale` command in this README.

```bash
tailscale status --json | grep -E '"BackendState"|"MagicDNSEnabled"|"CertDomains"|ts\.net"$'
tailscale serve status
```

When things are ready, the first command prints lines like these. Device and tailnet names differ for every setup.

```text
  "BackendState": "Running",
    "MagicDNSEnabled": true
  "CertDomains": [
    "my-mac.tail1234.ts.net"
```

- `"BackendState": "Running"` means this computer is logged in to Tailscale and connected.
- `"MagicDNSEnabled": true` means MagicDNS is on.
- The name on the line after `"CertDomains"` is the name this computer can get an HTTPS certificate for, which means HTTPS certificates are enabled. Input page addresses start with `https://<that name>/`. If no name appears, as in `"CertDomains": null`, HTTPS certificates are off; switch them on in the DNS page above.
- `tailscale serve status` shows what Serve currently publishes. With no other Serve configuration it prints "No serve config". If the command ends without an error, this computer can use Serve commands. If it fails, look up the error message in the [Tailscale Serve docs](https://tailscale.com/docs/features/tailscale-serve), fix it and run the command again.

## Install, enable, disable, remove

Run these commands on the computer running Hermes.

### Install and enable

Download the repository:

```bash
git clone https://github.com/junhoolee/hermes-secure-input.git ~/hermes-secure-input
```

Create a link named exactly `secure-input` in Hermes's user plugin folder, pointing to the downloaded folder:

```bash
mkdir -p ~/.hermes/plugins
ln -s ~/hermes-secure-input ~/.hermes/plugins/secure-input
```

Enable the plugin. Hermes does not load a user plugin until it is enabled.

```bash
hermes plugins enable secure-input
```

Check that it is in place:

```bash
hermes plugins list --user
hermes plugins doctor secure-input
hermes tools list --platform slack
```

- `hermes plugins list --user` should show `secure-input` as `enabled`.
- `hermes plugins doctor secure-input` should print "OK: runtime discovery, manifest parsing, import, and registration passed".
- `hermes tools list --platform slack` should show `secure_input` as `enabled`. `secure_input` is the toolset that holds this plugin's two tools (`secure_input_request` and `secure_input_enter_code`); `enabled` means the agent in Slack conversations can use them.
- If something differs, see the first entry of [Troubleshooting](#troubleshooting).

Finally restart the gateway. The gateway looks for plugins only once, when it starts, so the tools and the command appear in Slack only after a restart.

```bash
hermes gateway restart
```

Restart the gateway with this command even if you only use CLI conversations. Every other place in this README that says to restart the gateway applies to CLI conversations too.

### If the tool is disabled for Slack

If `hermes tools list --platform slack` shows `secure_input` as disabled, enable it and restart the gateway. This can happen if you once disabled this tool for Slack.

```bash
hermes tools enable secure_input --platform slack
hermes gateway restart
```

### Using it in other profiles

Plugin folders and the enabled setting are per profile.
To use the plugin in a profile other than `default` (for example `worker`), create the link in that profile's folder too and enable it there:

```bash
mkdir -p ~/.hermes/profiles/worker/plugins
ln -s ~/hermes-secure-input ~/.hermes/profiles/worker/plugins/secure-input
hermes -p worker plugins enable secure-input
hermes gateway restart
```

Three rules apply when you work with another profile. They apply to every install, check, disable, remove and settings command in this README.

- **Link path**: the `default` profile's link is `~/.hermes/plugins/secure-input`; another profile's link is `~/.hermes/profiles/<profile>/plugins/secure-input`. Change the path given to `mkdir`, `ln -s` and `rm` accordingly.
- **`-p <profile>`**: `hermes plugins ...`, `hermes tools ...`, `hermes config ...` and `hermes vault ...` apply to a profile when you put `-p <profile>` right after `hermes`, for example `hermes -p worker plugins list --user` or `hermes -p worker tools list --platform slack`. Without `-p` they apply to the active profile. That is `default` unless you changed it with `hermes profile use`; if you did, also add `-p default` to the `hermes` commands in [Install and enable](#install-and-enable).
- **Gateway restart**: once, not once per profile. In the standard setup a single gateway started by the `default` profile handles the conversations of every profile, so whichever profile you changed, run `hermes gateway restart` once. It reconnects every profile's messengers. If you changed the active profile with `hermes profile use`, run `hermes -p default gateway restart` instead.

To see whether a profile runs on the shared gateway, run `hermes -p <profile> gateway status`.
If the first line is "✓ Gateway is running via the default-profile multiplexer", that profile shares the `default` gateway.
If the first line is "✗ Gateway is not running", no gateway is handling that profile's conversations right now; first check with `hermes -p default gateway status` that the `default` gateway is running.
Any other first line means the profile runs its own gateway. After changing that profile, restart its gateway with `hermes -p <profile> gateway restart` instead of `hermes gateway restart`.

The plugin's settings (the two interception settings in [Intercepting Hermes's own prompts](#intercepting-hermess-own-prompts-on-by-default-can-be-switched-off), `keychain_items`, `allowed_tailscale_logins`) are per profile. The plugin reads the settings of the profile of the conversation the request came from, not of the profile the value is saved to.

### Letting the plugin write to an existing Keychain item (`keychain_items`)

To put a new value, through a Keychain password request, into a Keychain item that a script on this Mac already reads, list that item in the allow list `keychain_items`.
The plugin does not write to Keychain items that are not on the allow list, except its own items (whose `service` starts with `hermes-secure-input.`).

Each allow-list entry needs all five fields:

- `id`: the name the agent and the command pass. 1 to 40 characters of lowercase letters, digits and `-`, starting with a lowercase letter or a digit.
- `service`, `account`: the two names of the existing Keychain item. Up to 128 characters of letters, digits, `.`, `_`, `@` and `-`, starting with a letter or a digit.
- `label`: one line (up to 120 characters) saying what the value is.
- `used_by`: one line (up to 120 characters) saying which program reads the value.

A made-up example. Always write the whole list at once:

```bash
hermes config set plugins.entries.secure-input.settings.keychain_items '[{"id": "nightly-backup", "service": "backup-script", "account": "backup", "label": "Backup script password", "used_by": "the backup script that runs every night"}]'
hermes gateway restart
```

- The agent sees each entry's `id`, `label` and `used_by` in the tool description. `service` and `account` are not in the tool description. The tool description is built when the gateway starts, which is why the example restarts the gateway. Requests, including `!secure-input secret <id>`, always use the current setting, so only the agent's knowledge of a new entry waits for the restart.
- When a request is made, the entry's `service` appears in the Slack message and in the result the agent receives. `account` does not; it is shown only on the input page. This computer's audit log also records `account` (see [Audit log](#audit-log)).
- If the agent passes, as `keychain_item`, a name equal to an entry's `service` or `account` (ignoring case) instead of its `id`, the tool makes no request and instead answers which allow-list entry (`id`) uses that name. This comparison runs before the name rules are checked, so a guessed name containing `.` or `@` is compared too. The answer never shows an `account`, but it does tell the agent whether a guessed name matches one, and Slack shows nothing about such a check.
- Entries that break the rules are left out of the list: entries with a missing or an extra field, entries whose field text breaks the rules above, entries whose `service` starts with `hermes-secure-input.`, and entries with the same `id` as an earlier entry.
- Only the first 20 valid entries are used; the rest are left out with a warning in the log. The allow list goes into the tool description every time the agent calls the model, so 20 entries make the tool description up to about 6,000 characters longer.
- Each left-out entry leaves one warning line in the Hermes log, `secure-input: keychain_items item <number> left out (field <field name>)`. Entries left out for going over the limit leave just one line, with the number of the first such entry and the field name `limit`. The warning never contains field text.
- If the `id` of a left-out entry is passed, the plugin treats it as a name that is not on the allow list, so it writes to its own item (`service` `hermes-secure-input.<id>`) instead of the existing item. If that item does not exist yet, the page shows the "새 항목입니다…" (This is a new item…) note from [Keychain item names](#keychain-item-names). If you see that note in a request that was meant for an existing item, do not send; check the allow list again.

The plugin writes to an existing Keychain item (on the allow list or plugin-owned) only if `/usr/bin/security` is in that item's access list. The access list is the list of programs the Keychain lets read that item.
To check this condition, run the same check the plugin runs, from the downloaded folder. Put the item's `service` and `account` in place of `backup-script` and `backup`. The check does not read the value and writes nothing.

```bash
cd ~/hermes-secure-input
python3 -c 'from secure_input.stores import keychain; print(keychain.preflight({"service": "backup-script", "account": "backup"}))'
```

- `{'available': True, 'reason': None, 'exists': True}`: the item exists and the plugin can write to it.
- `{'available': False, 'reason': 'keychain_acl_denied', 'exists': True}`: the item exists, but `/usr/bin/security` is not in its access list, so the plugin will not write to it. Items set to "Allow all applications to access this item" in Keychain Access also give this result, because the check passes only if `/usr/bin/security` is literally on the list. Slack and the agent's result show it as `keychain_acl_denied: 접근 허용 목록에 /usr/bin/security 없음` (/usr/bin/security not in the access list). In both of these cases, save to a plugin-owned item under a new name that is not in `keychain_items`, and change the script to read that item.
- `{'available': True, 'reason': None, 'exists': False}`: no item has those names. For an allow-list entry, saving creates a new item with those names. The input page then shows on the Keychain row: "허용 목록에 적힌 이름의 항목이 키체인에 아직 없습니다. 보내면 이 이름으로 새 항목을 만듭니다. 보내기 전에, 허용 목록에 적은 키체인 항목 이름과 키체인 계정 이름이 맞는지 확인하세요." (The Keychain has no item with the names on the allow list yet. Sending creates a new item with these names. Before sending, check that the item name and account name on the allow list are right.) Check that `service` and `account` are not mistyped.
- If `python3` is not found, use the Python Hermes uses, which in a standard install is `~/.hermes/hermes-agent/.venv/bin/python`. The check uses only the Python standard library, so any Python 3 works.

### Disable

Disable the plugin and restart the gateway. The files stay.

```bash
hermes plugins disable secure-input
hermes gateway restart
```

### Remove

Disable it first, then delete the link. The path given to `rm` is the link, so the downloaded folder is not deleted.
Do not use `hermes plugins remove secure-input` for this kind of install: it fails with "Error: Plugin 'secure-input' is a link to ..., outside the plugins directory" and deletes nothing, so delete the link with `rm`.

```bash
hermes plugins disable secure-input
rm ~/.hermes/plugins/secure-input
hermes gateway restart
```

To delete the downloaded folder as well:

```bash
rm -rf ~/hermes-secure-input
```

Removing the plugin does not remove values already saved. They live in each profile's `.env` and vault and in the macOS Keychain, not in the plugin folder. How to delete them is in [Finding and deleting saved values](#finding-and-deleting-saved-values).

### Intercepting Hermes's own prompts (on by default, can be switched off)

While enabled, this plugin blocks two of Hermes's own behaviours and tells the agent to use this plugin's tools instead.
Both settings are on by default, so unless you change them both behaviours are blocked.
The interception does not depend on whether the conversation is Slack or CLI; it applies to every conversation of a profile where the plugin is enabled.

- Login one-time code entry (`enter_code` of `browser_vault`, Hermes's built-in vault tool): blocked because in Slack conversations Hermes asks for this code with a Slack modal.
- Saving a login (`browser_vault` `save_login`): in Slack conversations Hermes has no input field for this, so it tells you to add the login yourself in a terminal with `hermes vault add`. The plugin blocks that and has the agent send an input page link instead.

In CLI conversations Hermes asks for the one-time code and the login directly in an input field of that CLI screen. The code is shown as you type it; for a login it asks for the username and then takes the password hidden. This built-in way does not pass through Slack.
With interception on, CLI conversations also get an input page link instead of that input field.

To switch either interception off, set its setting to `false` with the commands below. The change applies from the next tool call, so no gateway restart is needed.
With the setting `false`, the plugin no longer blocks that Hermes behaviour.
The plugin's tools stay available, so the agent may use either the built-in way or an input page link.
To have only the built-in way, disable the plugin (see [Disable](#disable)).
For other profiles, use `hermes -p <profile> config set ...` as described above.

```bash
hermes config set plugins.entries.secure-input.settings.intercept_core_code_prompt false
hermes config set plugins.entries.secure-input.settings.intercept_core_save_login false
```

To switch it back on, run the same command with `true` instead of `false`. This also applies from the next tool call.

## Usage

### When the agent sends a link by itself

When the agent gets stuck for lack of a credential, it calls this plugin's tools on its own:

- When an API key is missing (the environment variable is empty, or the service returns an authentication error), it calls the `secure_input_request` tool for an API key.
- When it has opened a login page but no login is saved for that site, it calls the same tool for a website login.
- When a script on this Mac needs a password that it reads from the Keychain, it calls the same tool for a Keychain password.
- When a site asks for a one-time code during a login, it calls the `secure_input_enter_code` tool.

What you see, step by step:

**1.** The Hermes bot posts one message in the Slack conversation the request came from (inside the thread, if the conversation is a thread), with the content below and an "입력 페이지 열기" (open input page) button. The English translation is on the right of each line.

```text
자격증명 입력 요청: API 키                                    Credential request: API key
이름표: Exa API 키                                            Label: Exa API key
목적: Exa 웹 검색 도구를 쓰려면 API 키가 필요합니다            Purpose: the Exa web search tool needs an API key
변수: EXA_API_KEY                                             Variable: EXA_API_KEY
저장 위치: .env (페이지에서 켜고 끌 수 있음)                   Store: .env (can be switched on/off on the page)
키체인 항목(켜면 저장): hermes-secure-input.exa-api-key        Keychain item (saved if switched on): ...
  (계정 hermes-secure-input, 이 플러그인 전용 이름)              (account hermes-secure-input, a name owned by this plugin)
저장될 프로필: default (페이지에서 바꿀 수 있음)               Profile to save to: default (can be changed on the page)
60초 안에 열어야 하고 한 번만 열 수 있습니다.                   Open within 60 seconds; it opens only once.
연 뒤 5분 안에 제출하세요.                                     Submit within 5 minutes of opening.
```

For a website login there is a line such as `사이트: https://admin.example.com` (site) instead of `변수:`.
For a Keychain password the title is `자격증명 입력 요청: 비밀번호` (credential request: password), and instead of `저장될 프로필:` there is `로그를 남길 프로필: default (Mac 키체인은 프로필과 무관합니다)` (profile to log to: default (the macOS Keychain does not depend on profiles)).
For a one-time code there is no store line, and instead of `저장될 프로필:` it says "저장: 하지 않음(코드는 로그인 페이지에 바로 입력됩니다)" (saved: no (the code is typed straight into the login page)).

**2.** Pressing the button opens the input page. It shows who asked, the list of stores, the input fields, the time left and, for API keys and website logins, a box to choose the profile to save to.
Check the stores, enter the value and press "암호화해서 보내기" (encrypt and send). If you do not want to enter it, press "요청 취소" (cancel request); the page then changes to "요청을 취소했습니다" (request cancelled).

**3.** The page changes to "저장했습니다" (saved) and shows the result for each store. For a one-time code it changes to "전달했습니다" (handed over).
At the same time the Slack message loses its button and is replaced by a result line, for example:

```text
저장 완료: EXA_API_KEY, 프로필 default                                    saved: EXA_API_KEY, profile default
저장 완료: EXA_API_KEY, 프로필 default; Mac 키체인 hermes-secure-input.exa-api-key  saved: ..., and macOS Keychain ...
저장 완료: https://admin.example.com 로그인, 프로필 worker                 saved: login for https://admin.example.com, profile worker
저장 완료: Mac 키체인 hermes-secure-input.backup-script-password          saved: macOS Keychain ...
일부만 저장: EXA_API_KEY, 프로필 default; 실패: Mac 키체인 hermes-secure-input.exa-api-key(사유 keychain_write_failed) (API 키 'Exa API 키')
                                                                          partly saved: ...; failed: macOS Keychain ... (reason keychain_write_failed)
전달 완료: accounts.example.com 일회용 코드를 로그인 페이지로 넘겼습니다     handed over: the one-time code was passed to the login page
만료: 60초 안에 열리지 않았습니다 (API 키 'Exa API 키')                     expired: not opened within 60 seconds
취소: 사용자가 입력 페이지에서 취소했습니다 (API 키 'Exa API 키')            cancelled: the user cancelled on the input page
```

**4.** The agent receives the result. The result never contains the value. What happens next depends on the type.
What the agent receives is listed under "What this plugin gives the model" in [Security](#security-the-path-a-value-takes).

- Website login: once saved, the agent fills the login page with that vault item and carries on.
- One-time code: once handed over, Hermes types the code into the login page's code field and the agent carries on.
- Keychain password: once saved, the agent receives the name of the Keychain item. The script that needs the value reads it from the Keychain itself.
- API key: even when saved, the agent does not carry on with the work that needed the key. It tells you what to do, as in [After an API key is saved](#after-an-api-key-is-saved).

The agent waits for the result before going on, for at most 6 minutes 40 seconds (60 seconds to open + 5 minutes to submit + up to 30 seconds to save + 10 seconds of margin).

For a login one-time code, if the saved login has an authenticator setup key, Hermes makes the code and types it in without any link. A link is sent only when there is no setup key.

### After an API key is saved

Saving an API key writes it to `.env` (and to the Keychain, if selected). It does not put the key into the running Hermes.
With the result, the agent is told to tell you two things:

1. Restart the gateway once: send `!restart` in the Slack conversation, or run `hermes gateway restart` on the Hermes computer. The gateway finishes the work in progress and then restarts. If the profile you saved to runs its own gateway, restart that one with `hermes -p <profile> gateway restart`. If you sent `!restart`, a restart notice such as "♻ Gateway restarted successfully. Your session continues." appears in that conversation when the restart is done.
2. After the restart, ask again, in the same conversation, for the work that needed the key.

### Using an API key kept only in the Keychain

If you switch `.env` off and only the Keychain on when saving an API key, Hermes cannot read that key, because Hermes normally reads API keys from `.env`.
In that case the agent's result says "Hermes가 이 값을 쓰려면 본체 설정 `secrets.command`가 필요합니다." (Hermes needs its own setting `secrets.command` to use this value), together with the item's `service` and `account`.
`secrets.command` is a Hermes setting, not a setting of this plugin. When the gateway starts, it runs the command once for each profile that has the setting, and reads the `NAME=value` lines the command prints into that profile's environment.
The commands below make Hermes read `EXA_API_KEY` from the Keychain item `hermes-secure-input.exa-api-key`. Set it in the profile that uses the key (`-p <profile>` for another profile) and restart the gateway.

```bash
hermes config set secrets.command.enabled true
hermes config set secrets.command.command "printf 'EXA_API_KEY=%s\n' \"\$(/usr/bin/security find-generic-password -s hermes-secure-input.exa-api-key -a hermes-secure-input -w)\""
hermes gateway restart
```

- Type the commands as shown; the backslashes are for your shell, and the setting stores the command without them.
- A command of this shape was checked, with a test item, to make Hermes read the value from the Keychain on the Mac this plugin was built on.
- If `.env` or the gateway's own environment already has the same variable, Hermes uses that value and not the command's.
- If the command does not finish within 3 seconds, Hermes does not read any value from it.
- For several keys, make one command print several `NAME=value` lines. A profile has only one `secrets.command.command`.

**`.env` or Keychain for API keys?**
`.env` is a plain text file. If it is copied anywhere (a backup, a file attachment, an agent reading the file into a conversation), every key in it goes along. A Keychain item is encrypted and does not travel with copied files.
The Keychain does not protect against programs running as the same macOS user: Hermes must be able to read the key with no one around, so the plugin's items can be read by `/usr/bin/security` without a prompt, and so can the agent's terminal tool (see [What it does not protect against](#what-it-does-not-protect-against)).
The Keychain also adds a way to fail: if the keychain is locked when the gateway starts (for example, after a reboot before anyone logs in to the desktop, or when Hermes is started only over SSH), the command may not be able to read the key, and anything that needs the key then fails.

### Starting a request yourself with a command

To put in an API key, a login or a Keychain password ahead of time, start the link with a command.
In Slack, Hermes commands start with `!` (like Hermes's own `!restart`), as written below. In the Hermes CLI, write `/secure-input` instead. `key` starts an API key request, `login` a website login request and `secret` a Keychain password request.

```text
!secure-input key <variable name> [--profile <profile>] [--purpose "<purpose text>"] [--label "<label>"]
!secure-input login <https://site address> [--profile <profile>] [--purpose "<purpose text>"] [--label "<label>"]
!secure-input secret <Keychain item name> [--purpose "<purpose text>"] [--label "<label>"]
!secure-input help
```

Examples:

```text
!secure-input key EXA_API_KEY
!secure-input key OPENROUTER_API_KEY --profile worker --label "OpenRouter key"
!secure-input login https://admin.example.com --label "Example shop admin"
!secure-input secret backup-script-password --label "Backup script password"
```

- Variable names use only uppercase letters, digits and `_`, and do not start with a digit.
- Names Hermes uses for running programs or for security settings (for example `PATH`, `PYTHONPATH`, `HERMES_HOME`) and names starting with `SECURE_INPUT_` cannot be saved with this plugin. For such a name no link is made, and the reply starts with "이 변수 이름으로는 저장할 수 없습니다." (This variable name cannot be saved.)
- Site addresses must start with `https://`. If you send an address with a path, the plugin drops the path and keeps only the site address: `https://admin.example.com/login` is saved as `https://admin.example.com`.
- A site address with non-ASCII characters is saved as an ASCII address starting with `xn--`, and is shown that way in the Slack message and on the input page. For example, `https://한글.example` becomes `https://xn--bj0bj06e.example`.
- Keychain item names follow [Keychain item names](#keychain-item-names): an allow-list `id` writes to that existing item, any other name to a plugin-owned item.
- Without `--label`, the label is the variable name, the site's host name or the Keychain item name. Without `--purpose`, a default purpose text ending in "직접 등록합니다" (registering it myself) is used.
- The purpose text is one line of up to 200 characters, the label one line of up to 80 characters. If either contains a line break, a control character or an invisible formatting character (Unicode category Cf, for example U+200B zero-width space or U+202E right-to-left override), no link is made, and the refusal does not repeat that text. U+200D, which joins several emoji into one, is also a Cf character, so joined emoji such as the family emoji cannot be used in the purpose or the label. The same rules apply when the agent asks through the tool.
- The command has no option to choose stores. Stores are switched on and off on the input page.
- Never put the value in the command. The command only sends the link; the value goes only into the input page.
- One-time codes cannot be started with a command. The agent sends a one-time code link during a login.

After the command, Hermes replies right away, for example "입력 링크를 보냈습니다(변수 EXA_API_KEY, 프로필 default). 결과는 링크 메시지에 표시됩니다." (Input link sent (variable EXA_API_KEY, profile default). The result will appear in the link message.)
The link message, input page and result that follow are the same as when the agent sends the link.

The CLI has no Slack buttons. In a CLI conversation the same content as the Slack message appears as a text message in the conversation, with the link address on the last line as `입력 페이지 열기: https://...` (open input page).
Open that address in a browser on a device in the tailnet.
When the request ends, the result line appears in the same conversation.

### Choosing the profile to save to

`.env` and the vault are per profile, so a profile to save to is chosen.
By default it is the profile of the conversation the request came from. For example, a request from a conversation running as the `worker` profile saves to `worker`.
There are three ways to change it:

- Agent tool argument: the agent puts a profile name in `target_profile` when it calls `secure_input_request`.
- Command option: add `--profile <profile>` to the command.
- The "저장할 프로필" (profile to save to) box on the input page: choose from this computer's Hermes profiles. The box starts with the profile chosen by the two ways above. If you change it, the value is saved to the profile you chose.

The box also lists profiles where this plugin is not installed. If you choose one, the value is still saved to that profile's `.env` or vault. Using a saved value does not need the plugin.

The macOS Keychain does not depend on profiles. Keychain passwords and one-time codes have no box for choosing a profile.

## How long a link lives

- A link must be opened within 60 seconds of being made.
- A link opens only once. Opening it again shows "이미 열린 링크입니다" (this link was already opened).
- After opening, you have 5 minutes to send the value. The 5 minutes count from when the link is opened and keep running while saving. If 5 minutes pass while not saving, the page erases what you typed and changes to "제출 시간이 지났습니다" (submission time is over).
- After you press send, the page says "저장 중입니다. 이 창을 닫지 마세요." (saving, do not close this window). While saving, neither the 5-minute limit nor "요청 취소" (cancel request) stops the save. The plugin finishes the save and reports the result in the Slack message and to the agent. A save that succeeds is reported as saved, even if the 5 minutes ran out while it was running.
- Saving itself has a time limit: 10 seconds for `.env`, 30 seconds for the vault and 20 seconds for the Keychain, added up over the selected stores. Only an API key can select two stores (`.env` and Keychain, 30 seconds together), so saving takes at most 30 seconds. If saving does not finish in that time, the plugin stops it. If at least one store was saved by then, the result is "일부만 저장했습니다" (only partly saved). If no store was confirmed saved, the request ends as failed: the page says "저장했는지 알 수 없습니다" (cannot tell whether it was saved) and the Slack message starts with "저장 여부를 확인하지 못했습니다." (could not confirm whether it was saved).
- If sending a value fails, you can send again. After 5 failures the request ends.
- When the plugin cannot tell whether a save worked, the request ends at once as failed (see the Troubleshooting entry that starts with "저장했는지 알 수 없습니다"). Otherwise, a failure is when the Hermes computer received what was sent but could not decrypt or save it: the content had the wrong format, decryption failed, none of the selected stores could be saved, or the value looked masked.
- A send where the pre-write check found a store that cannot be written, so nothing was written, does not count as a failure.
- A try that never reached the Hermes computer because of a broken connection does not count either. The page then says "Hermes 컴퓨터에 연결하지 못했습니다. 연결을 확인하고 다시 보내세요." (could not connect to the Hermes computer; check the connection and send again).
- A site saying the password or code is wrong does not count as a failure. The plugin does not check values against the site.
- At most 3 requests can be open at the same time on one computer, across all profiles.
- When a request ends (saved, partly saved, handed over, expired, cancelled, failed), the server that served its input page stops, and its address is removed from Tailscale Serve. That address never opens again.
- If you missed a link or entered a wrong value, ask the agent again or send the command again. Each time a new link is made.

## Security: the path a value takes

The path a value takes, and who cannot see it on each part of the path:

| Part of the path | Protection | Who cannot see the value here |
|---|---|---|
| Inside the browser of the device you type on | The browser encrypts the value before sending, with a key made fresh for each request (browser-standard WebCrypto, ECDH key exchange and AES-GCM encryption). | Anyone who can see the request after it leaves the device and before the input page server decrypts it |
| From that device to the Hermes computer | Tailscale encrypts the connection between devices ([What is Tailscale?](https://tailscale.com/docs/concepts/what-is-tailscale)); inside it, Tailscale Serve's HTTPS encrypts again. | People on the same Wi-Fi or the same stretch of internet |
| Inside the Hermes computer, from Tailscale Serve to the input page server | After HTTPS ends, the request body still holds only the value the browser encrypted. | Tailscale Serve, and any program logging requests on this stretch |
| The input page server | The server decrypts the value in memory and saves it right away. The value is never written to a log. | People reading the audit log |
| Storage | The value goes into the stores you selected (`.env`, vault, macOS Keychain). A one-time code is typed into the login page and discarded. | Who can read stored values is in [What it does not protect against](#what-it-does-not-protect-against). |

What goes to Slack and what does not:

- Goes: the link address, purpose text, type, label, profile to save to, stores, the variable name or site address or Keychain item name (`service`), reasons the agent gave, and the result status. For a plugin-owned item, the Keychain account name (always `hermes-secure-input`) goes too. For an allow-list entry, its `id`, `label` and `used_by` go too.
- Does not go: the value (API key, password, authenticator setup key, one-time code), the login username, and the Keychain account name (`account`) of an allow-list entry. An allow-list entry's account name appears only on the input page, which opens only over Tailscale.

What the AI model sees and does not see:

- What this plugin gives the model: the result status, request number (`request_id`, also in the audit log), type, label, profile saved to, the result for each store, the variable name or site address or Keychain item name (`service`), the vault item handle, and guidance sentences (short Korean instructions, such as what to tell you next). The vault item handle is a name that points to a saved login item. For a plugin-owned item it also gives the Keychain account name (always `hermes-secure-input`). For an allow-list entry it gives the entry's `id` and `label` (the tool description also has `used_by`).
- What this plugin does not give the model: the value, the login username, the link address, and the Keychain account name (`account`) of an allow-list entry.
- However, Hermes itself shows login usernames when it lists saved logins, so the agent can see the usernames saved in the vault. Passwords and authenticator setup keys are not in that list.
- When Hermes fills a login page with a saved login, it types the password into the page directly; the model does not see it.

Only devices that can reach this computer in the same tailnet can reach the input page.
If your tailnet has access rules, they apply to Serve too ([Tailscale Serve docs](https://tailscale.com/docs/features/tailscale-serve)).
The page is not published to the internet; the plugin does not use Tailscale Funnel, Tailscale's feature for publishing to the internet.
Each link address contains an unguessable random string made fresh for each request. If the path of an address does not start with that string, the server answers 404 with "찾을 수 없습니다." (not found).
The plugin adds to and removes from Tailscale Serve only the one address of its own request. It does not touch any other Serve configuration.

### Which Tailscale accounts can open a link

- The input page opens only on devices logged in to an allowed Tailscale account. The input page server decides from the Tailscale account that Tailscale Serve adds to each request it forwards (the `Tailscale-User-Login` request header).
- By default the only allowed account is the one the Hermes computer's Tailscale is logged in to.
- Opening the link on a device with another account shows "이 기기의 Tailscale 계정으로는 열 수 없습니다" (this device's Tailscale account cannot open it). The link is not used up by this, so within 60 seconds of the link being made you can still open it on a device with the allowed account.
- See the Hermes computer's account with the two lines below on the Hermes computer (`plutil` comes with macOS). See the typing device's account in its Tailscale app.

```bash
uid=$(tailscale status --json | plutil -extract Self.UserID raw -o - -)
tailscale status --json | plutil -extract "User.$uid.LoginName" raw -o - -
```

- The second line prints the logged-in account name on one line, like `someone@example.com` or `octocat@github`.
- To allow other accounts, put them in the setting `allowed_tailscale_logins`: a list of accounts allowed in addition to the Hermes computer's own, empty by default. Write the whole list at once, as below. A change applies from the next request, so no gateway restart is needed.

```bash
hermes config set plugins.entries.secure-input.settings.allowed_tailscale_logins '["someone@example.com", "other@example.com"]'
hermes config set plugins.entries.secure-input.settings.allowed_tailscale_logins '[]'
```

- The second line removes all additional accounts.
- The plugin reads this setting from the profile of the conversation the request came from. So for someone else to open links from conversations running as `worker`, put it in `worker` with `hermes -p worker config set ...`. The setting of the profile the value is saved to is not read.
- An account in this setting can open the links of every request from that profile's conversations. There is no way to choose accounts per request.

## What it does not protect against

- Someone else using a device logged in to an allowed Tailscale account (for example a shared PC logged in to the same account) can open the link first, within the 60 seconds. The plugin checks accounts, not devices. Whoever opens it first cannot see values already saved, but can enter a value of their choosing and have it saved. If you then open the link, you get "이미 열린 링크입니다" (this link was already opened). If you see that without having opened it, ask for a new link and enter the value again.
- Programs running inside the Hermes computer can reach the input page server directly, without going through Tailscale Serve, and can send any `Tailscale-User-Login` header they like. The account check therefore does not stop them.
- The link button is visible to everyone in that Slack conversation.
- If the computer running Hermes itself is compromised, nothing is protected, because that computer decrypts and saves the values.
- A saved `.env` is a plain text file. The plugin writes it with permissions that let only the owner read and write it, but programs running as the same user on that computer can read the values.
- The vault encrypts all saved items (site address, username, password, authenticator setup key) into one file. In the default setup, the key that decrypts that file is the `vault.key` file in the same folder, so programs running as the same user on this computer can use that key to decrypt and read the vault.
- Values in the macOS Keychain can be read with the `security` command by programs of the same macOS user logged in on this Mac. Hermes's terminal tool is one of them.
- An agent that can use the terminal tool can read and overwrite Keychain items directly with the `security` command. The same agent can also edit `keychain_items` in the configuration file itself. What the allow list stops is only the agent passing another item's name to this plugin's tool, for example after being misled by text on a web page.
- When you save to an existing Keychain item, its old value cannot be recovered. The plugin keeps no copy of it.
- During a username-and-password login, Hermes may not recognise a one-time code field labelled only in Korean (for example the "일회용 번호" (one-time number) field of the Korean portal Naver). Then no link is sent. The agent does not ask for the code in chat; it says that this site's code field cannot be filled automatically, and then either uses another way to log in that needs no code or stops the login. Separately, some sites offer other ways to log in, such as logging in with a one-time number or a QR code instead of a password; the description of this plugin's login request tool always tells the agent to use the username-and-password way on such sites. The plugin does not look at the login page to decide which way to log in.
- Sending the Slack button message relies on an internal part of the Hermes gateway. If Hermes changes and that part disappears, a plain text message containing the link address is sent instead of the button. The value still does not go to Slack.

## Finding and deleting saved values

There is no way to delete from every store at once. Use the copies record to see where copies are, and delete in each store separately.

### The copies record

- Location: `~/.hermes/secure-input/placements.json`, one file for all profiles. The plugin writes it with permissions that let only the owner read and write it.
- What is recorded: for each successful save, where each credential was saved. For `.env`, the profile and variable name; for the vault, the profile, site address and item handle (`item_id`); for the Keychain, `service` and `account`. The time of saving is recorded too.
- What is not recorded: values and login usernames. Stores where saving failed or where it is unknown whether saving worked are not recorded.
- The file records saves. It does not mean the value is still there. Deleting a value the ways below leaves the record in place.

### How to delete from each store

Delete a variable line from `.env` with the command below (for another profile, `hermes -p <profile> config unset ...`). The other lines stay. Restart the gateway afterwards so the running Hermes forgets the value too.

```bash
hermes config unset EXA_API_KEY
hermes gateway restart
```

Delete a vault login item by its handle, an item name starting with `vault_`, shown as `item_id` in the copies record or in the Handle column of `hermes vault list`. Put it in place of `<handle>` below (for another profile, `hermes -p <profile> vault ...`). Deleting prints "Removed <handle>".

```bash
hermes vault list
hermes vault rm <handle>
```

Delete a Keychain item by its `service` and `account`. This command does not print the value. Deleting prints "password has been deleted."

```bash
security delete-generic-password -s hermes-secure-input.exa-api-key -a hermes-secure-input
```

Find the Keychain items this plugin made (its own items, and the temporary items in [Leftover temporary Keychain items](#leftover-temporary-keychain-items)) with the command below. It shows only each item's `service` name, never the value. Allow-list items keep their own names and are not found this way; the copies record lists them.

```bash
security dump-keychain | grep '"svce"<blob>="hermes-secure-input\.'
```

### Leftover temporary Keychain items

The input page and Slack messages point to this section by its Korean name, "남은 임시 키체인 항목".

When changing a Keychain item that already has a value, the plugin first writes the value you entered to a temporary item, reads it back, and then writes the real item. An item that does not exist yet is written directly, without a temporary item.
A temporary item's `service` starts with `hermes-secure-input.tmp.` and its `account` is `hermes-secure-input`.
The plugin deletes the temporary item when saving ends. But if that deletion fails, or saving is stopped for running past its time limit, a temporary item holding the value you entered may be left behind.
In that case the input page (the save-failure notice, the end screen after it, and the completion screen) and the Slack result message add "임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다." (the value you entered may remain in a temporary Keychain item) and tell you to check and delete it with the commands in this section. The plugin does not delete leftover temporary items later.
The Slack result message at the end of a request and the tool result the agent receives describe what all tries of that request left in the Keychain, not just the last try:

- The temporary-item sentence is added if any try left a temporary item, whatever later tries did.
- The sentences saying that an existing item's old value may have changed, or that an item was newly created, are added if any try did that, unless a later try saved to that same Keychain item. In that case they are left out, because the item now holds the value reported as saved.

See whether temporary items are left with the command below. If it prints nothing, none are left.

```bash
security dump-keychain | grep '"svce"<blob>="hermes-secure-input\.tmp\.'
```

If some are left, delete each by putting the name in quotes from the printed line as `service`. The name below is an example.

```bash
security delete-generic-password -s hermes-secure-input.tmp.0123456789ab -a hermes-secure-input
```

## Audit log

Every time something happens to a request (made, opened, saved and so on), the plugin adds one line to an audit log file.

- Location: `logs/secure-input.jsonl` in the folder of the profile chosen when the request was made (if none was chosen, the profile of the conversation the request came from). For `default` that is `~/.hermes/logs/secure-input.jsonl`; for another profile, `~/.hermes/profiles/<profile name>/logs/secure-input.jsonl`.
- If you choose another profile on the input page, the lines from the save onward are written to the logs of both profiles, with the originally requested profile noted as `requested_profile`.
- The file is created with permissions that let only the owner read and write it.
- What is recorded: time, event type (made, opened, account refused, submitted, saving, saved, handed over, expired, cancelled, failed, server cleanup), request number, a short identifier standing in for the link address, the requester (agent or user, profile, platform, conversation identifier, the messenger's user ID), purpose text, type, label, profile to save to, the stores selected in advance and the reasons the agent gave, the variable name or site address, the Keychain item name (`service`) and Keychain account name (`account`), and failure reasons. The account name is recorded for allow-list entries too, although it is never sent to Slack or the agent.
- A save line (`saved`) has `detail.stores`, recording per store whether it was saved (`saved`), whether an old value was replaced (`replaced`), and the failure reason (`error`). The Keychain entry in `detail.stores` also records whether an item that existed before was written (`main_touched`), whether a missing item was written and so newly created (`main_created`), and whether a temporary item was left (`tmp_left`). For a partial save, `detail.partial` is `true`.
- A line that ends a request (saved, ended by failure, expired, cancelled) has `detail.keychain_left`, recording what may have been left in the Keychain by this and all earlier tries of the request (`main_touched`, `main_created`, `tmp_left`) and that item's `service`. If none of the three applies, the field is absent. It never contains the Keychain account name. The `keychain_left` in the tool result the agent receives has the same shape.
- Never recorded: values or their length, website login usernames, the link address itself, encryption keys, ciphertext.

## Troubleshooting

Each heading is a symptom; Korean text you see on screen is followed by its translation.

#### The install check does not give the expected result

If `hermes plugins list --user` does not list `secure-input`, or `hermes plugins doctor secure-input` says "ERROR: Plugin 'secure-input' was not found as a path or installed plugin id", check the link: `ls -l ~/.hermes/plugins/` should show a link named exactly `secure-input`, with the downloaded folder after the arrow.
If the list shows it as `not enabled`, or `hermes tools list --platform slack` does not list `secure_input`, run `hermes plugins enable secure-input`.
For another profile, change the link path and `-p` as in [Using it in other profiles](#using-it-in-other-profiles).
For other errors, doctor's `ERROR:` line names the step that failed and the original error (for example `ERROR: Plugin registration failed: No module named ...`). First bring the downloaded folder up to date with `git -C ~/hermes-secure-input pull` and run `hermes plugins doctor secure-input` again.
If the same error remains, check with `hermes --version` that Hermes is v0.23.3 or newer; v0.23.3 is the version this plugin was tested on (see [Requirements](#requirements)).
If the version is fine and the error remains, run `HERMES_PLUGINS_DEBUG=1 hermes plugins doctor secure-input`. This prints an error record starting with `Traceback` above the `ERROR:` line. Its last `File "…", line …` line is the file and line where the error happened, and the line right after it is the original error. Please report those two lines in a GitHub issue.

#### Pressing the button does not open the page, or the page says "Hermes 컴퓨터에 연결하지 못했습니다" (could not connect to the Hermes computer)

The typing device's Tailscale is off, or the device is in a different tailnet from the Hermes computer. Switch Tailscale on on that device and check it is the same tailnet.
Also check that the Hermes computer is on and that the readiness command in [Requirements](#requirements) shows `"BackendState": "Running"` there.
If your tailnet uses access rules (ACLs), check in the admin console that the typing device may reach port 443 of the Hermes computer ([Tailscale ACL docs](https://tailscale.com/docs/features/access-control/acls)).
A link whose request has already ended does not open either. That includes a link not opened within 60 seconds of being made; the Slack message then starts with "만료:" (expired). Opening such a link shows a connection-failure screen or a 404 (not found) in the browser. Ask for a new link.

#### "이미 열린 링크입니다" (this link was already opened)

The link has already been opened once, perhaps in another window or on another device logged in to an allowed Tailscale account. Ask for a new link.

#### "이 기기의 Tailscale 계정으로는 열 수 없습니다" (this device's Tailscale account cannot open it)

The device that opened the link is logged in to a Tailscale account that is not allowed. Look up the account in that device's Tailscale app and compare it with the Hermes computer's account, found with the commands in [Which Tailscale accounts can open a link](#which-tailscale-accounts-can-open-a-link).
The link was not used up, so within 60 seconds of it being made you can open it again on a device with the same account. After 60 seconds, ask for a new link.
If it has to open on someone else's device, add that person's account to `allowed_tailscale_logins`.

#### The agent or the command replies "Tailscale 계정을 확인하지 못해 입력 페이지를 띄우지 못했습니다" (could not start the input page because the Tailscale account could not be checked)

The plugin could not read the Hermes computer's Tailscale account. Check that the readiness command in [Requirements](#requirements) shows `"BackendState": "Running"`. If it does not, open the Tailscale app on the Hermes computer, log in and ask again.

#### Under the API key field: "API 키에는 영문, 숫자, 기호, 공백만 넣을 수 있습니다." (API keys may contain only letters, digits, symbols and spaces)

The pasted value contains other characters (for example Korean, full-width characters or an invisible line separator). Copy the key from the service's admin page again and paste it. The page catches this before sending, so it does not count toward the 5 failures.

#### "제출 시간이 지났습니다" (submission time is over) with "값은 링크를 연 뒤 5분 안에 보내야 합니다." (values must be sent within 5 minutes of opening the link)

Nothing was sent within 5 minutes of opening. The value went nowhere and the page erased what you typed. The Slack message also changes to a line starting with "만료: 연 뒤 5분 안에 제출되지 않았습니다" (expired: not submitted within 5 minutes of opening). Ask for a new link.

#### "제출 시간이 지났습니다" with "앞서 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다." (the value sent earlier was not saved, and the time ran out without sending again), or the Slack message "만료: 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다"

A value was sent but not saved (the notices "값을 저장하지 못했습니다" (could not save the value), "아무 데도 저장하지 않았습니다" (nothing was saved) or "가려진 값처럼 보여 저장하지 않았습니다" (not saved because it looks masked)), and 5 minutes passed after opening without sending again from the same page.
No store was reported as saved. The page erased what was left in the input fields.
If the page or the Slack message carries one of the Keychain sentences — "기존 값이 바뀌었을 수 있습니다" (the existing value may have changed), "새로 만들어졌고 이번에 넣은 값이 들어 있을 수 있습니다" (was newly created and may hold the value you entered), "임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다" (the value you entered may remain in a temporary Keychain item) — that Keychain item or temporary item may hold this value. If you sent several times from the same page, the sentence may come from an earlier try rather than the last one.
Ask for a new link and save again. Check for and delete temporary items with the commands in [Leftover temporary Keychain items](#leftover-temporary-keychain-items).

#### The Slack message starts with "만료: 저장하는 동안 제출 시간이 지났고 저장하지 못했습니다" (expired: the submission time ran out while saving, and nothing was saved), and the page says "저장했는지 알 수 없습니다" (cannot tell whether it was saved)

The value was sent in time, but saving did not succeed in any selected store, and by the time saving ended the 5 minutes were over. The page only says it could not confirm the result, because time was already up when the server answered. The Slack message is right: nothing was saved. If the Slack message carries one of the Keychain sentences above, that Keychain item or temporary item may hold this value. Ask for a new link and save again.

#### The page says "아무 데도 저장하지 않았습니다" (nothing was saved) with a store and a reason

The pre-write check found a selected store that cannot be written right now. Nothing was written, and it does not count as a failure.
If the reason starts with "이 키체인 항목의 접근 허용 목록에 /usr/bin/security가 없어서 Hermes가 이 항목의 값을 바꾸지 않습니다." (Hermes will not change this item because /usr/bin/security is not in its access list), `/usr/bin/security` is missing from that existing item's access list. Items set to "Allow all applications" give this reason too. Check with the check command in [Letting the plugin write to an existing Keychain item](#letting-the-plugin-write-to-an-existing-keychain-item-keychain_items); if it gives `keychain_acl_denied`, ask again under a new name as that section says.
If the reason is "Hermes가 도는 컴퓨터에서 키체인에 접근하지 못했습니다." (the Hermes computer could not reach the Keychain) or "Mac 키체인이 5초 안에 답하지 않았습니다." (the macOS Keychain did not answer within 5 seconds; each `security` command the plugin runs gets 5 seconds, separate from the 20-second save limit), check on the Hermes computer that `security default-keychain` prints a path such as `"/Users/<user>/Library/Keychains/login.keychain-db"`. If it does, send again from the same page; if not, the macOS default keychain has to be fixed first (not covered here).
After fixing the cause, send again from the same page. For an API key you can also switch that store off and send.

#### The page title is "일부만 저장했습니다" (only partly saved) and the Slack message starts with "일부만 저장:"

Only some of the selected stores were saved. Values in the saved stores stay. The page and the Slack message show, per store, whether it was saved and why not. How to fill in the rest is in [Saving to several stores](#saving-to-several-stores).

#### The page says "저장했는지 알 수 없습니다" (cannot tell whether it was saved), or the Slack message starts with "저장 여부를 확인하지 못했습니다." (could not confirm whether it was saved)

The page shows "저장했는지 알 수 없습니다" in two situations, and the Slack message tells them apart. If the Slack message starts with "만료: 저장하는 동안 제출 시간이 지났고 저장하지 못했습니다", see the entry above: nothing was saved. If it starts with "저장 여부를 확인하지 못했습니다.", the rest of this entry applies.
The save result could not be confirmed; the value may or may not have been saved. The request ended as failed, so you cannot send again from the same page. Ask for a new link and save again; saving to the same place replaces the value. If the Slack message adds "키체인 항목 `…`의 기존 값이 바뀌었을 수 있습니다." (the existing value of Keychain item `…` may have changed), that item's old value may already be gone.

#### The page says "값을 저장하지 못했습니다" (could not save the value) with a reason for each store

The Hermes computer received the value but could not write it to any selected store. This counts as one of the 5 failures. You can send again from the page.
If the Keychain row says "이 이름의 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다." (a Keychain item with this name was newly created and may hold the value you entered), the command that writes a missing item succeeded but reading the value back gave something different, so an item with that name now exists in the Keychain. If the write command itself failed, no item is created and this sentence does not appear.
If you send again from the same page and it saves, the item gets the new value. If you switch the Keychain off and save only to another store, the completion screen and the Slack result message repeat the sentence that the item was newly created. If you do not send again, you can delete the item with the Keychain command in [How to delete from each store](#how-to-delete-from-each-store); the plugin does not delete it. After this failure the Slack message stays as it was until the request ends, and then changes to a result line.
If this keeps happening with the vault, check whether the profile already has a vault but has lost only `vault/vault.key` (the `vault` folder is in the profile's folder, for `default` `~/.hermes/vault`). Without `vault.key`, Hermes cannot decrypt the existing vault and refuses to save. If a backup has that profile's `vault/vault.key`, put it back. If not, rename the `vault` folder (for example to `vault.old`) and send again; Hermes then makes a new vault and a new key, and the logins in the old vault have to be entered again.

#### The page says "보내지 못했습니다." (could not send) and "가려진 값처럼 보여 저장하지 않았습니다. 원래 키 전체를 붙여 넣어 주세요." (not saved because it looks masked; paste the whole original key)

The pasted value looks like a masked display such as `***`, `sk-abc...wxyz` or `[REDACTED]`, so Hermes refused to save it (error code `masked_value`). Nothing was written to any store. Copy the whole original key from the service's admin page and send again from the same page. This counts as one of the 5 failures.

#### "시도 횟수를 넘었습니다" (too many attempts)

Sending a value failed 5 times and the request ended. The Slack message changes to a failure line with the reason `too_many_attempts`: for an API key, a login or a Keychain password it starts with "실패: 저장하지 못했습니다" (failed: could not save), and for a one-time code with "실패: 코드를 로그인 페이지로 넘기지 못했습니다" (failed: could not pass the code to the login page).
If a failed try created a Keychain item or wrote to an existing one, the Slack message carries the Keychain sentences above. Check the Slack message for these sentences: it covers all five tries. Ask for a new link.

#### The agent or the command replies "입력 페이지를 띄우지 못했습니다(…)" (could not start the input page (…))

The cause is in the parentheses.

- "tailscale CLI not found": the Tailscale command-line tool was not found. This does not happen if `/Applications/Tailscale.app/Contents/MacOS/Tailscale` exists. If it does not exist and `which tailscale` in a terminal prints a path, put that path in `SECURE_INPUT_TAILSCALE_BIN` and restart the gateway, because the gateway process's `PATH` can differ from the terminal's. If `which tailscale` prints nothing either, this computer has no Tailscale command-line tool; install Tailscale with the quickstart in [Requirements](#requirements).
- "tailscale CLI failed to run": the tool the plugin picked could not be started. If you set `SECURE_INPUT_TAILSCALE_BIN`, check that a program exists at that path; the plugin uses that path even if nothing is there.
- "MagicDNS off?": switch MagicDNS on.
- "serve_add_failed": Tailscale Serve could not publish the address.
  1. Run the Tailscale readiness command in [Requirements](#requirements) and check that this computer's name appears on the line after `"CertDomains"`. If not, enable HTTPS in the admin console's DNS page and ask again.
  2. If the name is there, look at `"BackendState"` in the same output. If it is not `"Running"`, open the Tailscale app on the Hermes computer, log in and ask again.
  3. If it is `"Running"`, run `tailscale serve status`. If that fails, look up the error message in the [Tailscale Serve docs](https://tailscale.com/docs/features/tailscale-serve), fix it and ask again. This README does not cover fixes for individual Tailscale errors.
  4. If that command succeeds but the failure keeps happening, look at Tailscale's error message yourself; the plugin does not write it to the audit log or the Hermes log. Run `tailscale serve --bg --https=443 --set-path /secure-input-test http://127.0.0.1:9/secure-input-test` on the Hermes computer to add a test address; the cause of the failure is printed in the terminal. This test command has the same shape as the one the plugin uses, with only the path and port changed. `127.0.0.1:9` is an address with no server behind it; the test only checks whether Serve can add an address. On success it prints "Serve started and running in the background." Afterwards remove the address with `tailscale serve --https=443 --set-path /secure-input-test off` and check that `tailscale serve status` is the same as before the test. If the test command fails, look up its error message in the Tailscale Serve docs, fix it and ask again.
  5. If the test command succeeds but the plugin keeps failing, the `tailscale` in your terminal and the tool the plugin uses may be different programs. The plugin picks the tool in the order given in [Requirements](#requirements) (`SECURE_INPUT_TAILSCALE_BIN`, then `/Applications/Tailscale.app/Contents/MacOS/Tailscale`, then `tailscale` from `PATH`). Put the path of the tool picked that way in place of `tailscale` and run the test and removal commands again. The error message printed then is the one the plugin received.

#### "이미 열린 요청이 3개라 새 요청을 만들지 않았습니다" (no new request because 3 requests are already open)

This computer has 3 requests that have not ended. Ask again after an earlier request ends.

#### "프로필을 찾지 못해 요청을 만들지 않았습니다" (no request because the profile was not found)

The folder of the profile given in `--profile` or `target_profile` does not exist. Check profile names with `hermes profile list`.

#### The agent does not know the tool and asks for the password in chat, or Slack says `!secure-input` is an unknown command

The plugin is disabled, not installed in that conversation's profile, or the gateway was not restarted. For that profile, check `hermes -p <profile> plugins list --user` and `hermes -p <profile> tools list --platform slack`, and restart the gateway.

#### Slack got a plain text message with the link address instead of a button

The plugin could not send the Slack button message and sent a plain text message instead. The link works the same, and the value does not go to Slack.

## Development

Run the tests from the downloaded folder with the Python that comes with Hermes:

```bash
~/.hermes/hermes-agent/.venv/bin/python -m pytest tests -q
```

The test-only setting `allow_no_identity_header` (default `false`) accepts connections without account information when set to `true`. Never switch it on in a Hermes you actually use.

Building and testing the input page was checked with Node.js 22 (`node --version` printed `v22.23.1`) and npm 10.9.8; other major versions were not checked. Install Node.js from the [Node.js download page](https://nodejs.org/en/download).
After changing the input page, rebuild it in the `ui/` folder. The build is written to `secure_input/static/`; commit that folder along with your change.
Browser tests run with Playwright. The test configuration has two Chromium projects (`chromium-mobile`, `chromium-desktop`) and two WebKit projects. The commands below run only the two Chromium projects. The WebKit projects were not checked, because Playwright WebKit could not handle button clicks on the Mac this plugin was built on.

```bash
cd ui
npm ci
npx playwright install chromium
npm run build
npm run test
npx playwright test --project=chromium-mobile --project=chromium-desktop
```

Two scripts check the path through the real Tailscale Serve and macOS Keychain. Both use only fake values and delete the Keychain items they create.

- `scripts/real_roundtrip_v2.py`: runs six kinds of saves through the real input page server, the save process and `/usr/bin/security`, with a fake Tailscale.
- `scripts/live_tailscale_v2.py`: runs a save through a real Tailscale Serve address. It starts only when `tailscale serve status` says "No serve config".

Repository layout:

- `plugin.yaml` and `__init__.py` are what Hermes reads when it loads the plugin.
- `secure_input/` holds the agent tools and command registration, the input page server started for each request, Tailscale Serve handling, saving to each store, and the audit log.
- `secure_input/static/` is the built input page; its source is in `ui/`.
- `tests/` holds the Python tests; `scripts/` holds the scripts used to check against real Tailscale, macOS Keychain and Slack.
- `docs/` holds the contract between the server and the page (`docs/protocol.md`), notes on how the plugin hooks into Hermes (`docs/integration-notes.md`), and how one-time codes are handled (`docs/otp-code-feasibility.md`).

A Korean version of this README is in [README.ko.md](README.ko.md).

## License

[MIT](LICENSE)
