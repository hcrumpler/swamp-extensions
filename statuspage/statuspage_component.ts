/**
 * Statuspage component model — manage the individual pieces of infrastructure
 * listed on an Atlassian Statuspage.
 *
 * Wraps the `/pages/{page_id}/components` endpoints with a full CRUD lifecycle
 * plus a `sync` method for drift detection. The component status can be updated
 * to reflect outages (`operational`, `degraded_performance`, `partial_outage`,
 * `major_outage`, `under_maintenance`).
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  type ClientLogger,
  NotFoundError,
  statuspageRequest,
} from "./_lib/statuspage.ts";

/** Valid component statuses accepted by the Statuspage API. */
const ComponentStatus = z.enum([
  "operational",
  "under_maintenance",
  "degraded_performance",
  "partial_outage",
  "major_outage",
]);

const GlobalArgsSchema = z.object({
  pageId: z.string().min(1).describe("Statuspage page identifier"),
  apiKey: z.string().min(1).meta({ sensitive: true }).describe(
    "Statuspage API key (Authorization: OAuth <key>)",
  ),
  name: z.string().min(1).describe("Component display name"),
  description: z.string().default("").describe("Component description"),
  status: ComponentStatus.default("operational").describe(
    "Initial/desired component status",
  ),
  groupId: z.string().optional().describe(
    "Optional component group id to nest this component under",
  ),
  showcase: z.boolean().default(true).describe(
    "Whether to show uptime showcase for the component",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Persisted component state mirrored from the Statuspage API response. */
const ComponentSchema = z.object({
  id: z.string(),
  page_id: z.string(),
  name: z.string(),
  status: z.string(),
  description: z.string().nullable(),
  group_id: z.string().nullable(),
  showcase: z.boolean(),
  position: z.number(),
  created_at: z.string(),
  updated_at: z.string(),
});

type ComponentData = z.infer<typeof ComponentSchema>;

/** Shape of a component object returned by the Statuspage API. */
interface ApiComponent {
  id: string;
  page_id: string;
  name: string;
  status: string;
  description: string | null;
  group_id: string | null;
  showcase: boolean;
  position: number;
  created_at: string;
  updated_at: string;
}

/** Normalise an API component into the persisted resource shape. */
function toComponentData(c: ApiComponent): ComponentData {
  return {
    id: c.id,
    page_id: c.page_id,
    name: c.name,
    status: c.status,
    description: c.description ?? null,
    group_id: c.group_id ?? null,
    showcase: c.showcase,
    position: c.position,
    created_at: c.created_at,
    updated_at: c.updated_at,
  };
}

/** Build the request body for create/update from global arguments. */
function componentBody(
  globalArgs: GlobalArgs,
): Record<string, unknown> {
  const component: Record<string, unknown> = {
    name: globalArgs.name,
    status: globalArgs.status,
    description: globalArgs.description,
    showcase: globalArgs.showcase,
  };
  if (globalArgs.groupId !== undefined) {
    component.group_id = globalArgs.groupId;
  }
  return { component };
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

/** Model definition for a single Statuspage component. */
export const model = {
  type: "@hmcrum/statuspage-component",
  version: "2026.09.17.1",
  globalArguments: GlobalArgsSchema,
  resources: {
    component: {
      description: "Statuspage component state",
      schema: ComponentSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    create: {
      description: "Create the component (idempotent — reuses existing state)",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey, name } = context.globalArgs;
        context.logger.info("Creating Statuspage component {name}", { name });

        // Idempotency: if we already have state and the component still exists,
        // return its refreshed state instead of creating a duplicate.
        const existing = await context.readResource(INSTANCE) as
          | ComponentData
          | null;
        if (existing) {
          try {
            const current = await statuspageRequest<ApiComponent>(
              `/pages/${pageId}/components/${existing.id}`,
              { apiKey, signal: context.signal, logger: context.logger },
            );
            context.logger.info(
              "Component {id} already exists, reusing",
              { id: current.id },
            );
            const handle = await context.writeResource(
              "component",
              INSTANCE,
              toComponentData(current),
            );
            return { dataHandles: [handle] };
          } catch (error) {
            if (!(error instanceof NotFoundError)) throw error;
            context.logger.warning(
              "Stored component {id} is gone; creating a new one",
              { id: existing.id },
            );
          }
        }

        const created = await statuspageRequest<ApiComponent>(
          `/pages/${pageId}/components`,
          {
            method: "POST",
            apiKey,
            body: componentBody(context.globalArgs),
            signal: context.signal,
            logger: context.logger,
          },
        );
        const handle = await context.writeResource(
          "component",
          INSTANCE,
          toComponentData(created),
        );
        context.logger.info("Created component {id}", { id: created.id });
        return { dataHandles: [handle] };
      },
    },
    update: {
      description: "Update component attributes and status",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey } = context.globalArgs;
        const existing = await context.readResource(INSTANCE) as
          | ComponentData
          | null;
        if (!existing) {
          throw new Error("No component state found — run create first");
        }
        context.logger.info("Updating component {id}", { id: existing.id });

        const updated = await statuspageRequest<ApiComponent>(
          `/pages/${pageId}/components/${existing.id}`,
          {
            method: "PATCH",
            apiKey,
            body: componentBody(context.globalArgs),
            signal: context.signal,
            logger: context.logger,
          },
        );
        const handle = await context.writeResource(
          "component",
          INSTANCE,
          toComponentData(updated),
        );
        return { dataHandles: [handle] };
      },
    },
    delete: {
      description: "Delete the component from the status page",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey } = context.globalArgs;
        const existing = await context.readResource(INSTANCE) as
          | ComponentData
          | null;
        if (!existing) {
          throw new Error("No component state found — nothing to delete");
        }
        context.logger.info("Deleting component {id}", { id: existing.id });

        try {
          await statuspageRequest<null>(
            `/pages/${pageId}/components/${existing.id}`,
            {
              method: "DELETE",
              apiKey,
              signal: context.signal,
              logger: context.logger,
            },
          );
        } catch (error) {
          // Already gone — deletion is idempotent.
          if (!(error instanceof NotFoundError)) throw error;
          context.logger.warning(
            "Component {id} already deleted",
            { id: existing.id },
          );
        }
        return { dataHandles: [] };
      },
    },
    sync: {
      description: "Refresh stored component state from the live API",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: MethodContext,
      ): Promise<{ dataHandles: Array<{ name: string }> }> => {
        const { pageId, apiKey } = context.globalArgs;
        const existing = await context.readResource(INSTANCE) as
          | ComponentData
          | null;
        if (!existing) {
          throw new Error("No component state found — run create first");
        }

        try {
          const live = await statuspageRequest<ApiComponent>(
            `/pages/${pageId}/components/${existing.id}`,
            { apiKey, signal: context.signal, logger: context.logger },
          );
          const handle = await context.writeResource(
            "component",
            INSTANCE,
            toComponentData(live),
          );
          return { dataHandles: [handle] };
        } catch (error) {
          if (error instanceof NotFoundError) {
            context.logger.warning(
              "Component {id} not found during sync; marking not_found",
              { id: existing.id },
            );
            const handle = await context.writeResource("component", INSTANCE, {
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
