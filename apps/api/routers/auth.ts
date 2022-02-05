import { z } from "zod";
import { authenticateUser, createUser, hashPassword } from "../utils/auth";
import { createRouter, db } from "../utils/context";

export const authRouter = createRouter()
  .mutation("register", {
    input: z.object({
      username: z.string().min(3).max(10),
      email: z.string().email(),
      password: z.string().min(8),
    }),
    async resolve({ input }) {
      const user = await createUser(
        input.username,
        input.email,
        input.password
      );
      return user;
    },
  })
  .mutation("login", {
    input: z.object({
      username: z.string().min(3).max(10),
      password: z.string().min(8),
    }),
    async resolve({ input }) {
      const user = await authenticateUser(input.username, input.password);
    },
  });
