/**
 * Statuspage incident model — create and manage realtime incidents on an
 * Atlassian Statuspage.
 *
 * Wraps the `/pages/{page_id}/incidents` endpoints. Incidents move through the
 * lifecycle `investigating → identified → monitoring → resolved`. This model
 * exposes `create`, `update`, `resolve` (a convenience action that posts a
 * resolving update), `delete`, and `sync`.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  type ClientLogger,
  NotFoundError,
  statuspageRequest,
} from "./_lib/statuspage.ts";

/** Valid realtime incident statuses. */
const IncidentStatus = z.enum([
  "investigating",
  "identified",
  "monitoring",
  "resolved",
]);

/** Valid incident impact override values. */
const IncidentImpact = z.enum([
  "none",
  "maintenance",
  "minor",
  "major",
  "critical",
]);

const GlobalArgsSchema = z.object({
  pageId: z.string().min(1).describe("Statuspage page identifier"),
  apiKey: z.string().min(1).meta({ sensitive: true }).describe(
    "Statuspage API key (Authorization: OAuth <key>)",
  ),
  name: z.string().min(1).describe("Incident title"),
  status: IncidentStatus.default("investigating").describe(
    "Current incident status",
  ),
  body: z.string().default("").describe(
    "Incident update body posted with create/update",
  ),
  impactOverride: IncidentImpact.optional().describe(
    "Optional impact override; omit to let Statuspage compute impact",
  ),
  componentIds: z.array(z.string()).default([]).describe(
    "Component ids affected by this incident",
  ),
  deliverNotifications: z.boolean().default(true).describe(
    "Whether subscribers are notified on updates",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Persisted incident state mirrored from the Statuspage API response. */
const IncidentSchema = z.object({
  id: z.string(),
  page_id: z.string(),
  name: z.string(),
  status: z.string(),
  impact: z.string(),
  shortlink: z.string().nullable(),
  component_ids: z.array(z.string()),
  created_at: z.string(),
  updated_at: z.string(),
  resolved_at: z.string().nullable(),
});

type IncidentData = z.infer<typeof IncidentSchema>;

/** Shape of an incident object returned by the Statuspage API. */
interface ApiIncident {
  id: string;
  page_id: string;
  name: string;
  status: string;
  impact: string;
  shortlink: string | null;
  components?: Array<{ id: string }> | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

/** Normalise an API incident into the persisted resource shape. */
function toIncidentData(i: ApiIncident): IncidentData {
  return {
    id: i.id,
    page_id: i.page_id,
    name: i.name,
    status: i.status,
    impact: i.impact,
    shortlink: i.shortlink ?? null,
    component_ids: (i.components ?? []).map((c) => c.id),
    created_at: i.created_at,
    updated_at: i.updated_at,
    resolved_at: i.resolved_at ?? null,
  };
}

/** Build an incident request body for a given status/body. */
function incidentBody(
  globalArgs: GlobalArgs,
  overrides: { status?: string; body?: string } = {},
): Record<string, unknown> {
  const incident: Record<string, unknown> = {
    name: globalArgs.name,
    status: overrides.status ?? globalArgs.status,
    body: overrides.body ?? globalArgs.body,
    deliver_notifications: globalArgs.deliverNotifications,
  };
  if (globalArgs.impactOverride !== undefined) {
    incident.impact_override = globalArgs.impactOverride;
  }
  if (globalArgs.componentIds.length > 0) {
    incident.component_ids = globalArgs.componentIds;
  }
  return { incident };
}

const INSTANCE = "main";

interface MethodContext {
  globalArgs: GlobalArgs;
  signal?: AbortSignal;
  logger: ClientLogger;
  readResource: (
    name: string,
    version?: number,
  ) => Promise<Record<string, unknown> | null>;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Arguments for the `resolve` action. */
const ResolveArgsSchema = z.object({
  body: z.string().default("This incident has been resolved.").describe(
    "Resolution message posted as the final incident update",
  ),
});

/** Model definition for a single Statuspage incident. */
export const model = {
  type: "@hmcrum/statuspage-incident",
  version: "2026.09.17.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    incident: {
      description: "Statuspage incident state",
      schema: IncidentSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    create: {
      description: "Open a new incident (idempotent — reuses existing state)",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey, name } = context.globalArgs;
        context.logger.info("Creating Statuspage incident {name}", { name });

        const existing = await context.readResource(INSTANCE) as
          | IncidentData
          | null;
        if (existing) {
          try {
            const current = await statuspageRequest<ApiIncident>(
              `/pages/${pageId}/incidents/${existing.id}`,
              { apiKey, signal: context.signal, logger: context.logger },
            );
            context.logger.info(
              "Incident {id} already exists, reusing",
              { id: current.id },
            );
            const handle = await context.writeResource(
              "incident",
              INSTANCE,
              toIncidentData(current),
            );
            return { dataHandles: [handle] };
          } catch (error) {
            if (!(error instanceof NotFoundError)) throw error;
            context.logger.warning(
              "Stored incident {id} is gone; creating a new one",
              { id: existing.id },
            );
          }
        }

        const created = await statuspageRequest<ApiIncident>(
          `/pages/${pageId}/incidents`,
          {
            method: "POST",
            apiKey,
            body: incidentBody(context.globalArgs),
            signal: context.signal,
            logger: context.logger,
          },
        );
        const handle = await context.writeResource(
          "incident",
          INSTANCE,
          toIncidentData(created),
        );
        context.logger.info("Created incident {id}", { id: created.id });
        return { dataHandles: [handle] };
      },
    },
    update: {
      description: "Post an incident update with the current status and body",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey } = context.globalArgs;
        const existing = await context.readResource(INSTANCE) as
          | IncidentData
          | null;
        if (!existing) {
          throw new Error("No incident state found — run create first");
        }
        context.logger.info("Updating incident {id}", { id: existing.id });

        const updated = await statuspageRequest<ApiIncident>(
          `/pages/${pageId}/incidents/${existing.id}`,
          {
            method: "PATCH",
            apiKey,
            body: incidentBody(context.globalArgs),
            signal: context.signal,
            logger: context.logger,
          },
        );
        const handle = await context.writeResource(
          "incident",
          INSTANCE,
          toIncidentData(updated),
        );
        return { dataHandles: [handle] };
      },
    },
    resolve: {
      description: "Resolve the incident by posting a resolving update",
      arguments: ResolveArgsSchema,
      execute: async (
        args: z.infer<typeof ResolveArgsSchema>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey } = context.globalArgs;
        const existing = await context.readResource(INSTANCE) as
          | IncidentData
          | null;
        if (!existing) {
          throw new Error("No incident state found — run create first");
        }
        context.logger.info("Resolving incident {id}", { id: existing.id });

        const resolved = await statuspageRequest<ApiIncident>(
          `/pages/${pageId}/incidents/${existing.id}`,
          {
            method: "PATCH",
            apiKey,
            body: incidentBody(context.globalArgs, {
              status: "resolved",
              body: args.body,
            }),
            signal: context.signal,
            logger: context.logger,
          },
        );
        const handle = await context.writeResource(
          "incident",
          INSTANCE,
          toIncidentData(resolved),
        );
        return { dataHandles: [handle] };
      },
    },
    delete: {
      description: "Delete the incident from the status page",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey } = context.globalArgs;
        const existing = await context.readResource(INSTANCE) as
          | IncidentData
          | null;
        if (!existing) {
          throw new Error("No incident state found — nothing to delete");
        }
        context.logger.info("Deleting incident {id}", { id: existing.id });

        try {
          await statuspageRequest<ApiIncident>(
            `/pages/${pageId}/incidents/${existing.id}`,
            {
              method: "DELETE",
              apiKey,
              signal: context.signal,
              logger: context.logger,
            },
          );
        } catch (error) {
          if (!(error instanceof NotFoundError)) throw error;
          context.logger.warning(
            "Incident {id} already deleted",
            { id: existing.id },
          );
        }
        return { dataHandles: [] };
      },
    },
    sync: {
      description: "Refresh stored incident state from the live API",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey } = context.globalArgs;
        const existing = await context.readResource(INSTANCE) as
          | IncidentData
          | null;
        if (!existing) {
          throw new Error("No incident state found — run create first");
        }

        try {
          const live = await statuspageRequest<ApiIncident>(
            `/pages/${pageId}/incidents/${existing.id}`,
            { apiKey, signal: context.signal, logger: context.logger },
          );
          const handle = await context.writeResource(
            "incident",
            INSTANCE,
            toIncidentData(live),
          );
          return { dataHandles: [handle] };
        } catch (error) {
          if (error instanceof NotFoundError) {
            context.logger.warning(
              "Incident {id} not found during sync; marking not_found",
              { id: existing.id },
            );
            const handle = await context.writeResource("incident", INSTANCE, {
              ...existing,
              status: "not_found",
              updated_at: new Date().toISOString(),
            });
            return { dataHandles: [handle] };
          }
          throw error;
        }
      },
    },
  },
};
