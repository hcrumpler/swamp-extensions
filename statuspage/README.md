# @hmcrum/statuspage

Manage an [Atlassian Statuspage](https://www.atlassian.com/software/statuspage)
from swamp. Two model types wrap the Statuspage REST API v1 as typed resources
with a full CRUD lifecycle plus drift-detecting `sync`:

- **`@hmcrum/statuspage-component`** — the individual pieces of infrastructure
  listed on your status page. Create them, update their status
  (`operational`, `degraded_performance`, `partial_outage`, `major_outage`,
  `under_maintenance`), delete them, and sync live state.
- **`@hmcrum/statuspage-incident`** — realtime incidents. Open, update, resolve,
  delete, and sync. Incidents move through
  `investigating → identified → monitoring → resolved`.

## Authentication

All methods authenticate with a Statuspage API key sent as an
`Authorization: OAuth <key>` header. Obtain your key from **manage.statuspage.io
→ your avatar → API info**, and store it in a swamp vault — the `apiKey`
global argument is marked sensitive so its value is vaulted, not persisted in
plaintext.

You also need your **Page ID**, shown on the same API info screen.

```bash
# Store the API key in a vault, then reference it from the model definition.
swamp vault create <type> statuspage
# ... store your key under a chosen key name ...
```

## Usage

### Components

```bash
# Create a component model instance.
swamp model create @hmcrum/statuspage-component api-component

# Configure globalArguments (pageId, apiKey via vault expression, name, status).
# Then run the lifecycle:
swamp model @hmcrum/statuspage-component method run create api-component
swamp model @hmcrum/statuspage-component method run update api-component   # push new status
swamp model @hmcrum/statuspage-component method run sync   api-component   # refresh from live API
swamp model @hmcrum/statuspage-component method run delete api-component
```

Global arguments:

| Argument      | Required | Description                                                     |
| ------------- | -------- | --------------------------------------------------------------- |
| `pageId`      | yes      | Statuspage page identifier                                      |
| `apiKey`      | yes      | API key (sensitive — store in a vault)                          |
| `name`        | yes      | Component display name                                          |
| `description` | no       | Component description                                           |
| `status`      | no       | `operational` (default), `degraded_performance`, `partial_outage`, `major_outage`, `under_maintenance` |
| `groupId`     | no       | Component group id to nest under                                |
| `showcase`    | no       | Show uptime showcase (default `true`)                           |

### Incidents

```bash
swamp model create @hmcrum/statuspage-incident db-outage

swamp model @hmcrum/statuspage-incident method run create  db-outage
swamp model @hmcrum/statuspage-incident method run update  db-outage        # post an update
swamp model @hmcrum/statuspage-incident method run resolve db-outage        # resolve with a message
swamp model @hmcrum/statuspage-incident method run sync    db-outage
swamp model @hmcrum/statuspage-incident method run delete  db-outage
```

Global arguments:

| Argument               | Required | Description                                                          |
| ---------------------- | -------- | -------------------------------------------------------------------- |
| `pageId`               | yes      | Statuspage page identifier                                           |
| `apiKey`               | yes      | API key (sensitive — store in a vault)                               |
| `name`                 | yes      | Incident title                                                       |
| `status`               | no       | `investigating` (default), `identified`, `monitoring`, `resolved`    |
| `body`                 | no       | Incident update body posted with create/update                       |
| `impactOverride`       | no       | `none`, `maintenance`, `minor`, `major`, `critical`                  |
| `componentIds`         | no       | Component ids affected by this incident                              |
| `deliverNotifications` | no       | Notify subscribers on updates (default `true`)                       |

The `resolve` method accepts an optional `body` argument for the final
resolution message (defaults to `"This incident has been resolved."`).

## Behaviour notes

- **Idempotent create** — if state already exists and the resource is still live
  at Statuspage, `create` returns the existing state instead of creating a
  duplicate. If the stored resource was deleted externally (404), it creates a
  fresh one.
- **Idempotent delete** — a 404 during delete is treated as success.
- **Drift detection** — `sync` refreshes stored state from the live API, or
  writes a `status: "not_found"` marker if the resource is gone.
- **Rate limiting** — Statuspage limits API tokens to ~1 request/second. The
  client retries on HTTP 420/429 with exponential backoff, honouring
  `Retry-After` when present.

## Development

```bash
# Type-check
~/.swamp/deno/deno check *.ts _lib/*.ts

# Test
~/.swamp/deno/deno test --allow-net .
```

## License

MIT — see [LICENSE.md](LICENSE.md).
