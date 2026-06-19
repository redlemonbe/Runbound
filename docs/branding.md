# White-label branding (#25)

Runbound can be re-branded for white-label / multi-tenant deployments: a custom
product name, logo, accent colour, favicon, and an *About* tab tailored to your
organisation. Branding is a **Web UI concern only** — it is never exposed by, nor
affects, the REST API or the DNS datapath.

Branding is driven entirely by configuration files; there is no in-UI editor.

---

## Enable it

Branding lives in a **dedicated file** so it stays out of your main config and
can be shipped/versioned separately. Two steps:

1. In the main config (`runbound.conf`), turn it on:

   ```
   server:
       branding: yes
   ```

2. Drop a file named exactly **`branding.conf`** in the **same directory** as the
   main config (e.g. `/etc/runbound/branding.conf`).

When `branding: yes` and the file exists, Runbound loads it at startup. If the
file is missing, Runbound logs a warning and falls back to the built-in defaults
(and to any `ui-brand-*` directives still present in the main config). When
`branding: no` (the default) the file is ignored even if present.

> Changes are read at startup — restart the service (or reload the config) to
> apply an edit.

---

## `branding.conf` keys

Same `key: value` syntax as the main config. Values may be quoted, and a `#`
**inside double quotes is not treated as a comment**, so hex colours work.

### Identity

| Key | Example | Default | Effect |
|-----|---------|---------|--------|
| `brand-name` | `"ACME DNS"` | `Runbound` | Header, login screen, browser tab title. |
| `accent-color` | `"#7c3aed"` | `#22d3ee` | Theme accent (tabs, brand text). Any CSS colour; **quote hex values**. |
| `logo-url` | `"https://acme.example/logo.svg"` | (built-in globe) | Logo image URL shown in the header. |
| `favicon-url` | `"https://acme.example/fav.ico"` | (built-in) | Browser favicon. |

### About tab (optional)

These populate a card on the **About** tab. All three are rendered **escaped**
(plain text / validated link) — no HTML injection.

| Key | Example | Effect |
|-----|---------|--------|
| `about-org` | `"ACME Corporation"` | Organisation name. |
| `about-text` | `"Internal resolver — open a ticket with IT."` | Free-text blurb. |
| `about-support-url` | `"https://acme.example/support"` | Support link (must be `http(s)://`; otherwise ignored). |

---

## Example

`/etc/runbound/runbound.conf`:

```
server:
    ui-enabled: yes
    ui-port:    8091
    branding:   yes
```

`/etc/runbound/branding.conf`:

```
brand-name:        "ACME DNS"
accent-color:      "#7c3aed"
logo-url:          "https://acme.example/logo.svg"
favicon-url:       "https://acme.example/fav.ico"

about-org:         "ACME Corporation"
about-text:        "Internal resolver — open a ticket with IT for support."
about-support-url: "https://acme.example/support"
```

A ready-to-edit copy ships at [`examples/branding.conf`](../examples/branding.conf).

---

## Where it shows up

| Field | Rendered in |
|-------|-------------|
| `brand-name` | Header logo text, login screen, `<title>`. |
| `accent-color` | Active tab underline/text and brand text colour. |
| `logo-url` | Header. |
| `favicon-url` | Browser tab icon. |
| `about-*` | A card at the top of the **About** tab. |

---

## Backwards compatibility

The older main-config directives — `ui-brand-name`, `ui-brand-logo-url`,
`ui-accent-color`, `ui-favicon-url` — still work as a fallback and are not
removed. When `branding: yes` and `branding.conf` is present, the dedicated file
takes precedence. For new deployments, prefer the dedicated file (it is the only
way to customise the About tab).

See also: [configuration.md → White-label branding file](configuration.md) and
[web-ui.md](web-ui.md).
