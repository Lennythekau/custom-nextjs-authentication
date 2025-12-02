import { userRoles } from "@/drizzle/schema";
import { redisClient } from "@/redis/redis";
import crypto from "crypto";
import { z } from "zod";

const SESSION_EXPIRATION_SECONDS = 60 * 60 * 24 * 7;
const COOKIE_SESSION_KEY = "custom-auth-session-id";  // name of the cookie

const sessionSchema = z.object({
    id: z.string(),
    role: z.enum(userRoles),
})

type UserSession = z.infer<typeof sessionSchema>;

export type Cookies = {
    set: (
        key: string,
        value: string,
        options: {
            secure?: boolean,
            httpOnly?: boolean,
            sameSite?: "strict" | "lax",
            expires: number
        }
    ) => void,
    get: (key: string) => { name: string, value: string } | undefined,
    delete: (key: string) => void;
}

export async function getUserFromSession(cookies: Pick<Cookies, "get">) {
    // Get the session id from the cookies
    const sessionId = cookies.get(COOKIE_SESSION_KEY)?.value;
    if (sessionId == null) return null;

    // Then grab the user session with this session id.
    return await getUserSessionById(sessionId);
}

export async function createUserSession(user: UserSession, cookies: Cookies) {

    // create a new random session id.
    const sessionId = crypto.randomBytes(512).toString("hex").normalize();

    // store session in redis cache for quicker access than database.
    await redisClient.set(`session:${sessionId}`, sessionSchema.parse(user), {
        ex: SESSION_EXPIRATION_SECONDS
    });

    setCookie(sessionId, cookies);
}

function setCookie(sessionId: string, cookies: Pick<Cookies, "set">) {
    cookies.set(COOKIE_SESSION_KEY, sessionId, {
        secure: true,
        httpOnly: true,
        sameSite: "lax",
        expires: Date.now() + SESSION_EXPIRATION_SECONDS * 1000,
    })
}

async function getUserSessionById(sessionId: string) {
    // grab the user from the redis cache.
    const rawUser = await redisClient.get(`session:${sessionId}`);

    const { success, data: user } = sessionSchema.safeParse(rawUser);

    return success ? user : null;
}

export async function removeUserFromSession(cookies: Pick<Cookies, "get" | "delete">) {
    const sessionId = cookies.get(COOKIE_SESSION_KEY)?.value;
    console.log(sessionId);
    if (sessionId == null) return null;
    await redisClient.del(`session:${sessionId}`);
}

export async function updateUserSessionData(user: UserSession, cookies: Pick<Cookies, "get" | "set">) {
    const sessionId = cookies.get(COOKIE_SESSION_KEY)?.value;

    if (sessionId == null)
        return null;

    await redisClient.set(`session:${sessionId}`, sessionSchema.parse(user), {
        ex: SESSION_EXPIRATION_SECONDS
    });

    setCookie(sessionId, cookies);

}

export async function updateUserSessionExpiration(cookies: Pick<Cookies, "get" | "set">) {
    const sessionId = cookies.get(COOKIE_SESSION_KEY)?.value;

    if (sessionId == null) return null;

    const user = await getUserSessionById(sessionId);
    if (user == null) return;

    await redisClient.set(`session:${sessionId}`, user, {
        ex: SESSION_EXPIRATION_SECONDS
    });
}