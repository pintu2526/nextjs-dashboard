import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";
import type { User } from "@/app/lib/definitions";
import bcrypt from "bcrypt";
import postgres from "postgres";

const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      credentials: {
        email: { label: "Email", type: "text", placeholder: "you@example.com" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        const schema = z.object({
          email: z.string().email(),
          password: z.string().min(6).max(100),
        });
        const result = schema.safeParse(credentials);
        if (!result.success) {
          throw new Error("Invalid credentials");
        }
        // Add your own logic here to find the user
        if (result.success) {
          const { email, password } = result.data;
          const user = await getUser(email);
          if (!user) return null;
          const isValidPassword = await bcrypt.compare(password, user.password);
          if (isValidPassword) return user;
        }
        console.log("User: invalidate password");
        return null;
      },
    }),
  ],
});
