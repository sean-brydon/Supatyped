import { PrismaClient } from "@prisma/client";
import * as trpc from "@trpc/server";
import * as trpcExpress from "@trpc/server/adapters/express";
import { verifyToken } from "./auth";

// Ensure that there's only a single Prisma instance in dev. This is detailed here:
// https://www.prisma.io/docs/support/help-articles/nextjs-prisma-client-dev-practices
declare global {
  var __globalPrisma__: PrismaClient;
}

export let db: PrismaClient;

if (process.env.NODE_ENV === "production") {
  db = new PrismaClient({
    log: ["error", "warn"],
  });
} else {
  if (!global.__globalPrisma__) {
    global.__globalPrisma__ = new PrismaClient({
      log: ["query", "error", "warn"],
    });
  }

  db = global.__globalPrisma__;
}

interface ContextWithUser extends trpcExpress.CreateExpressContextOptions {
  user?: {
    id: string;
    username: string;
  };
}
// Create TRPC context
export const createContext = ({ req, res, user }: ContextWithUser) => {
  if (req.headers.authorization) {
    const token = req.headers.authorization.split(" ")[1];
    const payload = verifyToken(token);
    return {
      user: {
        id: payload.id,
      },
      res,
      req,
    };
  }
  return { req, res };
};
export type Context = trpc.inferAsyncReturnType<typeof createContext>;

// Setup helper function to create routers
export function createRouter() {
  return trpc.router<Context>();
}

export function createProtectedRouter() {
  return trpc.router<Context>().middleware(({ ctx, next }) => {
    if (!ctx.user) {
      throw new trpc.TRPCError({ code: "UNAUTHORIZED" });
    }
    return next({
      ctx: {
        ...ctx,
        // infers that `user` is non-nullable to downstream procedures
        user: ctx.user,
      },
    });
  });
}
