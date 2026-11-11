<h1 align="center">UNVEIL</h1>

<p align="center">
  A self-hosted AI agent workspace with a security layer built into every agent action.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#security-layer">Security Layer</a> ·
  <a href="website/setup.md">Setup Guide</a> ·
  <a href="ROADMAP.md">Roadmap</a>
</p>

---

UNVEIL is a fork of [Odysseus](https://github.com/odysseus-dev/odysseus), maintained by Unveil Research Center LLC. It keeps Odysseus's chat, agents, research, documents, email, notes and calendar, and adds the ARAD runtime monitor to the core. Odysseus is the work of its authors and contributors, credited in [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md). Both projects are licensed under the [GNU AGPL-3.0](LICENSE). Internal names (the `odysseus` package, `ODYSSEUS_*` settings, storage keys) are unchanged so upstream updates still apply.

## Quick Start

```bash
git clone https://github.com/unveilzero/UNVEIL.git
cd UNVEIL
cp .env.example .env
docker compose up -d --build
```

Open `http://localhost:7011` when the containers are healthy. The first admin password is printed in `docker compose logs odysseus`.

The compose files build the image from this source. They do not pull the upstream Odysseus image, which does not contain the security layer.

## Security Layer

Every tool call an agent makes is checked by ARAD ([agent-runtime-anomaly-detector](https://github.com/unveilzero/agent-runtime-anomaly-detector)) as the last step before it runs. The check comes after Odysseus's own permission and approval system and can only deny.

- **Decisions.** Each call is allowed or blocked and written to a keyed, hash-chained audit log. The interface shows green when cleared and red when something was blocked.
- **Sequences.** Reading credential material and then sending data out is blocked, within one chat, across a user's chats, and inside a single command.
- **Outside tool servers.** Calls to MCP servers are checked too, including scheduled ones that no user started.
- **Background watch.** A timer re-verifies the audit log, the security files and the tool dispatcher whether or not anyone is signed in. A failure stops all agent actions until an administrator clears it.

Settings: `UNVEIL_GUARD_MODE` (`enforce` or `observe`), `UNVEIL_GUARD_PROFILE` (`standard` or `strict`), `UNVEIL_GUARD_WINDOW` (seconds), `UNVEIL_WATCH_INTERVAL` (seconds), `UNVEIL_AUDIT_KEY`.

The guard runs inside the application process and sees the actions agents take through UNVEIL. It is not an operating-system sandbox or antivirus. For the strongest setup, supply `UNVEIL_AUDIT_KEY` from outside the host and keep the application's own approval settings on.

Native installs, GPU notes, Windows/macOS instructions, HTTPS, and configuration live in the [setup guide](website/setup.md).

## Features

- **Chat + Agents** — local/API models, tools, MCP, files, shell, skills, and memory.
- **Cookbook** — hardware-aware model recommendations, downloads, and serving.
- **Deep Research** — multi-step web research with source reading and report generation.
- **Compare** — blind side-by-side model testing and synthesis.
- **Documents** — writing-first editor with AI edits, suggestions, Markdown, HTML, CSV, and syntax highlighting.
- **Email** — IMAP/SMTP inbox with triage, tags, summaries, reminders, and reply drafts.
- **Notes, Tasks + Calendar** — reminders, todos, scheduled agent tasks, and CalDAV sync.
- **Extras** — gallery/image editor, themes, uploads, web search, presets, sessions, and 2FA.

## Demo

The upstream [Odysseus landing page](https://odysseus-dev.github.io/odysseus/) has a hover-to-play tour of the interface UNVEIL is built on. The pages under [`website/`](website/), including the setup guide, are upstream's and still say Odysseus; use this repository's URL wherever they tell you to clone.

## Contributing

Help is welcome. The best entry points are fresh-install testing, provider setup bugs, mobile/editor polish, docs, and small focused refactors. See [CONTRIBUTING.md](CONTRIBUTING.md) and [ROADMAP.md](ROADMAP.md).

## Security

UNVEIL is a self-hosted workspace with powerful local tools. Keep auth enabled, keep private data out of Git, and do not expose raw model/service ports publicly.

- Keep `AUTH_ENABLED=true` for any network-accessible deployment.
- Keep `LOCALHOST_BYPASS=false` outside local development.

Deployment details are in the [setup guide](website/setup.md#security-notes).

## License

AGPL-3.0-or-later -- see [LICENSE](LICENSE) and [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).
