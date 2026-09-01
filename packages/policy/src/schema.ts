import { z } from 'zod';

/**
 * Policy document schema. Parsed from `infra/policy.yaml` and validated before
 * the POP will start — a malformed policy must fail loudly at boot rather than
 * silently degrade into "allow nothing" or, far worse, "allow everything".
 */

/** A hostname pattern: exact (`wiki.internal`) or single-label wildcard (`*.internal`). */
const hostPattern = z
  .string()
  .min(1)
  .refine((h) => !h.includes('*') || /^\*\.[^*]+$/.test(h), {
    message: 'wildcards must be of the form *.suffix',
  });

export const appSchema = z.object({
  id: z.string().min(1),
  hosts: z.array(hostPattern).min(1),
  ports: z.array(z.number().int().min(1).max(65535)).min(1),
  connector: z.string().min(1),
});

export const ruleSchema = z.object({
  id: z.string().min(1).optional(),
  app: z.string().min(1),
  allow: z
    .object({
      groups: z.array(z.string().min(1)).optional(),
      users: z.array(z.string().min(1)).optional(),
    })
    .refine((a) => (a.groups?.length ?? 0) + (a.users?.length ?? 0) > 0, {
      message: 'a rule must name at least one group or user, otherwise it allows everyone',
    }),
});

export const policySchema = z
  .object({
    apps: z.array(appSchema).min(1),
    rules: z.array(ruleSchema),
  })
  .superRefine((doc, ctx) => {
    const ids = new Set<string>();
    for (const app of doc.apps) {
      if (ids.has(app.id)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `duplicate app id: ${app.id}` });
      }
      ids.add(app.id);
    }
    for (const rule of doc.rules) {
      if (!ids.has(rule.app)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `rule references unknown app: ${rule.app}`,
        });
      }
    }
  });

export type PolicyApp = z.infer<typeof appSchema>;
export type PolicyRule = z.infer<typeof ruleSchema>;
export type PolicyDocument = z.infer<typeof policySchema>;
