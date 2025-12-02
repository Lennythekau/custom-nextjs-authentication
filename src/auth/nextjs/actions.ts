"use server"

import { z } from "zod"
import { redirect } from "next/navigation"
import { signInSchema, signUpSchema } from "./schemas"
import { db } from "@/drizzle/db"
import { UserTable } from "@/drizzle/schema"
import { eq } from "drizzle-orm"
import { comparePasswords, generateSalt, hashPassword } from "../core/passwordHasher"
import { createUserSession, removeUserFromSession } from "../core/session"
import { cookies } from "next/headers"

const UNABLE_TO_CREATE_ACCOUNT_MESSAGE = "Unable to create account";
const UNABLE_TO_LOGIN_MESSAGE = "Unable to create account";

export async function signIn(unsafeData: z.infer<typeof signInSchema>) {
  const { success, data } = signInSchema.safeParse(unsafeData)

  if (!success) return UNABLE_TO_LOGIN_MESSAGE;

  const user = await db.query.UserTable.findFirst({
    columns: { password: true, salt: true, id: true, email: true, role: true },
    where: eq(UserTable.email, data.email)
  })

  if (user == null) {
    return UNABLE_TO_LOGIN_MESSAGE;
  }

  const isCorrectPassword = await comparePasswords({
    hashedPassword: user.password!,
    password: data.password,
    salt: user.salt!
  })

  if (!isCorrectPassword) return UNABLE_TO_LOGIN_MESSAGE;

  await createUserSession(user, await cookies());

  redirect("/")
}

export async function signUp(unsafeData: z.infer<typeof signUpSchema>) {
  // validate data
  const { success, data } = signUpSchema.safeParse(unsafeData);
  if (!success) return UNABLE_TO_CREATE_ACCOUNT_MESSAGE;

  // ensure we don't already have a user with this email.
  const existingUser = await db.query.UserTable.findFirst({ where: eq(UserTable.email, data.email) });
  if (existingUser != null) return "Account already exists for this email";

  try {
    // generate a salt for a hash
    const salt = generateSalt();
    const hashedPassword = await hashPassword(data.password, salt);

    // save the user into the database.
    const [user] = await db
      .insert(UserTable)
      .values({
        name: data.name,
        email: data.email,
        password: hashedPassword,
        salt
      })
      .returning({ id: UserTable.id, role: UserTable.role });

    if (user == null) return UNABLE_TO_CREATE_ACCOUNT_MESSAGE;
    // if successful, then create a session in the database.
    await createUserSession(user, await cookies());
  } catch {
    return UNABLE_TO_CREATE_ACCOUNT_MESSAGE;
  }

  redirect("/");
}

export async function logOut() {
  await removeUserFromSession(await cookies());
  redirect("/");
}
