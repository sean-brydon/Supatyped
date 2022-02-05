import { User } from "@prisma/client";
import { TRPCError } from "@trpc/server";
import crypto from "crypto";
import { bcrypt, bcryptVerify } from "hash-wasm";
import { db } from "./context";
import { sign, verify } from "jsonwebtoken";
import { Response } from "express";

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);

  return await bcrypt({
    password,
    salt,
    costFactor: 10,
    outputType: "encoded",
  });
}

export async function comparePasswords(
  password: string,
  hashedPassword: string
): Promise<boolean> {
  return bcryptVerify({
    password,
    hash: hashedPassword,
  });
}

export async function logout(res: Response) {
  sendRefreshToken(res, "");
  return true;
}

export async function authenticateUser(
  username: string,
  password: string,
  res: Response
) {
  const user = await db.user.findUnique({ where: { username } });

  if (!user) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "Invalid username or password",
    });
  }

  const isPasswordValid = await comparePasswords(password, user.hashedPassword);

  if (!isPasswordValid) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "Invalid username or password",
    });
  }

  sendRefreshToken(res, createRefreshToken(user));

  return {
    user: {
      id: user.id,
      username: user.username,
    },
    accesToken: createAccessToken(user),
  };
}

export async function createUser(
  username: string,
  email: string,
  password: string
) {
  const user = await db.user.findUnique({ where: { username } });
  if (user) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "User already exists",
    });
  }

  return await db.user.create({
    data: {
      username,
      email,
      hashedPassword: await hashPassword(password),
    },
    select: {
      hashedPassword: false,
    },
  });
}

export async function revokeRefreshTokensForUser(userId: string) {
  await db.user.update({
    where: {
      id: userId,
    },
    data: {
      tokenVersion: {
        increment: 1,
      },
    },
  });
  return true;
}

// Tokens
export async function createAccessToken(user: User) {
  return sign(
    { user: { id: user.id, username: user.username } },
    process.env.JWT_SECRET!,
    { expiresIn: "15m" }
  );
}

export const createRefreshToken = (user: User) => {
  return sign(
    { userId: user.id, tokenVersion: user.tokenVersion },
    process.env.REFRESH_TOKEN_SECRET!,
    {
      expiresIn: "7d",
    }
  );
};

export const sendRefreshToken = (res: Response, token: string) => {
  res.cookie("refreshToken", token, {
    httpOnly: true,
    path: "/refresh_token",
  });
};

export function verifyToken(token: string) {
  return verify(token, process.env.JWT_SECRET!) as {
    id: string;
    username: string;
  };
}
