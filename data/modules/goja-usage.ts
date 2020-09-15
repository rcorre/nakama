
/**
 * The context of the current execution; used to observe and pass on cancellation signals.
 */
type ContextKey = "env" | "execution_mode" | "node" | "query_params" | "user_id" | "username" | "vars" | "user_session_exp" | "session_id" | "client_ip" | "client_port" | "match_id" | "match_node" | "match_label" | "match_tick_rate"
type Context = { [K in ContextKey]: string };

/**
 * An RPC function definition.
 */
interface RpcFunction {
    /**
     * An RPC function to be executed when called by ID.
     *
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param payload - The input data to the function call. This is usually an escaped JSON object.
     * @returns A response payload or error if one occurred.
     */
    (ctx: Context, logger: Logger, nk: Nakama, payload: string): string;
}

/**
 * A Before Hook function definition.
 */
interface BeforeHookFunction {
    /**
     * A Register Hook function definition.
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param payload - The input data to the function call. This is usually an escaped JSON object.
     * @returns A escaped JSON payload
     */
    (ctx: Context, logger: Logger, nk: Nakama, payload: string): string;
}

/**
 * A Aftter Hook function definition.
 */
interface AfterHookFunction {
    /**
     * A Register Hook function definition.
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param payload - The input data to the function call. This is usually an escaped JSON object.
     */
    (ctx: Context, logger: Logger, nk: Nakama, payload: string);
}

/**
 * The injector used to initialize features of the game server.
 */
interface Initializer {
    /**
     * Register an RPC function by its ID to be called as a S2S function or by game clients.
     *
     * @param id - The ID of the function in the server.
     * @param func - The RPC function logic to execute when the RPC is called.
     * @returns An error or null if no error occured.
     */
    registerRpc(id: string, func: RpcFunction);
    /**
     * Register a hook function to be run before an RPC function is invoked.
     * The RPC call is identified by the id param..
     *
     * @param id - The ID of the RPC function.
     * @param func - The Hook function logic to execute before the RPC is called.
     */
    registerReqBefore(id: string, func: BeforeHookFunction): string;
    /**
     * Register a hook function to be run after an RPC function is invoked.
     * The RPC call is identified by the id param..
     *
     * @param id - The ID of the RPC function.
     * @param func - The Hook function logic to execute after the RPC is called.
     * @returns An error or null if no error occured.
     */
    registerReqAfter(id: string, func: AfterHookFunction);
    /**
     * Register a hook function to be run before an RPC function is invoked.
     * The RPC call is identified by the id param..
     *
     * @param id - The ID of the RPC function.
     * @param func - The Hook function logic to execute before the RPC is called.
     */
    registerRtBefore(id: string, func: BeforeHookFunction): string;
    /**
     * Register a hook function to be run after an RPC function is invoked.
     * The RPC call is identified by the id param..
     *
     * @param id - The ID of the RPC function.
     * @param func - The Hook function logic to execute after the RPC is called.
     * @returns An error or null if no error occured.
     */
    registerRtAfter(id: string, func: AfterHookFunction);

    // TODO
}

/**
 * A structured logger to output messages to the game server.
 */
interface Logger {
    /**
     * Log a messsage with optional formatted arguments at DEBUG level.
     *
     * @param format - A string with optional formatting placeholders.
     * @param args - The placeholder arguments for the formatted string.
     * @returns The formatted string logged to the server.
     */
    debug(format: string, ...args: any[]): string;
    /**
     * Log a messsage with optional formatted arguments at WARN level.
     *
     * @param format - A string with optional formatting placeholders.
     * @param args - The placeholder arguments for the formatted string.
     * @returns The formatted string logged to the server.
     */
    warn(format: string, ...args: any[]): string;
     /**
     * Log a messsage with optional formatted arguments at ERROR level.
     *
     * @param format - A string with optional formatting placeholders.
     * @param args - The placeholder arguments for the formatted string.
     * @returns The formatted string logged to the server.
     */
    error(format: string, ...args: any[]): string;
    /**
     * A logger with the key/value pair added as the fields logged alongside the message.
     *
     * @param key - The key name for the field.
     * @param value - The value for the field.
     * @returns The modified logger with the new structured fields.
     */
    withField(key: string, value: string): Logger;
    /**
     * A new logger with the key/value pairs added as fields logged alongside the message.
     *
     * @param pairs - The pairs of key/value fields to add.
     * @returns The modified logger with the new structured fields.
     */
    withFields(pairs: {[key: string]: string}): Logger;
    /**
     * The fields associated with this logger.
     *
     * @returns The map of fields in the logger.
     */
    getFields(): {[key: string]: string};
}

/**
 * Request method type
 */
type RequestMethod = "get" | "post" | "put" | "patch"

/**
 * HTTP Response type
 */
interface HttpResponse {
    /**
     * Http Response status code.
     */
    code: number;
    /**
     * Http Response headers.
     */
    headers: string[];
    /**
     * Http Response body.
     */
    body: string;
}

/**
 * Object returned on successful user authentication
 */
interface AuthResult {
    /**
     * Authenticated User ID.
     */
    user_id: string;
    /**
     * Authenticated Username.
     */
    username: string;
    /**
     * New user created
     */
    created: boolean;
}

/**
 * Object returned on authentication token generation
 */
interface TokenGenerateResult {
    /**
     * Authentication token
     */
    token: string;
    /**
     * Token expire - Unix epoch
     */
    exp: number;
}

/**
 * Account object
 */
interface Account {
    user_id: string;
    username: string;
    display_name: string;
    avatar_url: string;
    lang_tag: string;
    location: string;
    timezone: string;
    apple_id: string;
    facebook_id: string;
    facebook_instant_game_id: string;
    google_id: string;
    gamecenter_id: string;
    steam_id: string;
    online: boolean;
    edge_count: string;
    create_time: number;
    update_time: number;
    metadata: object;
    wallet: {[key: string]: number},
    email: string;
    devices: {[key: string]: string}[];
    custom_id: string;
    verify_time: number;
    disable_time: number;
}

/**
 * User object
 */
interface User {
    user_id: string;
    username: string;
    display_name: string;
    avatar_url: string;
    lang_tag: string;
    location: string;
    timezone: string;
    apple_id: string;
    facebook_id: string;
    facebook_instant_game_id: string;
    google_id: string;
    gamecenter_id: string;
    steam_id: string;
    online: boolean;
    edge_count: string;
    create_time: number;
    update_time: number;
    metadata: object;
}

/**
 * User update account object
 */
interface UserUpdateAccount {
    username: string;
    display_name: string;
    avatar_url: string;
    lang_tag: string;
    location: string;
    timezone: string;
    metadata: object;
}

/**
 * The server APIs available in the game server.
 */
interface Nakama {
    /**
     * Emit an event to be processed.
     *
     * @param eventName - A string with the event name.
     * @param properties - A map of properties to send in the event.
     * @param timestamp - (optional) Timestamp of the event as a Unix epoch.
     * @param external - (optional) External (client side) generated event.
     */
    event(eventName: string, properties: {[key: string]: string}, timestamp?: number, external?: boolean);

    /**
     * Generate a new UUID v4.
     *
     * @returns UUID v4
     */
    uuidV4(): string

    /**
     * Execute an SQL query to the Nakama database.
     *
     * @param sqlQuery - SQL Query string.
     * @param arguments - List of arguments to map to the query placeholders.
     */
    sqlExec(sqlQuery: string, args: any[])

    /**
     * Get the results of an SQL query to the Nakama database.
     *
     * @param sqlQuery - SQL Query string.
     * @param arguments - List of arguments to map to the query placeholders.
     */
    sqlQuery(sqlQuery: string, args: any[])

    /**
     * Http Request
     *
     * @param url - Request target URL.
     * @param method - Http method.
     * @param headers - Http request headers.
     * @param body - Http request body.
     * @param timeout - Http Request timeout in ms.
     * @returns Http response
     */
    httpRequest(url: string, method: RequestMethod, headers: {[header: string]: string}, body: string, timeout?: number): HttpResponse

    /**
     * Base 64 Encode
     *
     * @param string - Input to encode.
     * @returns Base 64 encoded string.
     */
    base64Encode(s: string, padding?: boolean): string

    /**
     * Base 64 Decode
     *
     * @param string - Input to decode.
     * @returns Decoded string.
     */
    base64Decode(s: string, padding?: boolean): string

    /**
     * Base 64 URL Encode
     *
     * @param string - Input to encode.
     * @returns URL safe base 64 encoded string.
     */
    base64UrlEncode(s: string, padding?: boolean): string

    /**
     * Base 64 URL Decode
     *
     * @param string - Input to decode.
     * @returns Decoded string.
     */
    base64UrlDecode(s: string, padding?: boolean): string

    /**
     * Base 16 Encode
     *
     * @param string - Input to encode.
     * @returns URL safe base 64 encoded string.
     */
    base64UrlEncode(s: string, padding?: boolean): string

    /**
     * Base 16 Decode
     *
     * @param string - Input to decode.
     * @returns Decoded string.
     */
    base64UrlDecode(s: string, padding?: boolean): string

    /**
     * Generate a JWT token
     *
     * @param algorithm - JWT signing algorithm.
     * @param signingKey - Signing key.
     * @param claims - JWT claims.
     * @returns signed JWT token.
     */
    jwtGenerate(s: 'HS256' | 'RS256', signingKey: string, claims: {[key: string]: string}): string

    /**
     * AES 128 bit block size encrypt
     *
     * @param input - String to encrypt.
     * @param key - Encryption key.
     * @returns cipher text base64 encoded.
     */
    aes128Encrypt(input: string, key: string): string

    /**
     * AES 128 bit block size decrypt
     *
     * @param input - String to decrypt.
     * @param key - Encryption key.
     * @returns clear text.
     */
    aes128Decrypt(input: string, key: string): string

    /**
     * AES 256 bit block size encrypt
     *
     * @param input - String to encrypt.
     * @param key - Encryption key.
     * @returns cipher text base64 encoded.
     */
    aes256Encrypt(input: string, key: string): string

    /**
     * AES 256 bit block size decrypt
     *
     * @param input - String to decrypt.
     * @param key - Encryption key.
     * @returns clear text.
     */
    aes256Decrypt(input: string, key: string): string

    /**
     * MD5 Hash of the input
     *
     * @param input - String to hash.
     * @returns md5 Hash.
     */
    md5Hash(input: string): string

    /**
     * SHA256 Hash of the input
     *
     * @param input - String to hash.
     * @returns sha256 Hash.
     */
    sha256Hash(input: string): string

    /**
     * RSA SHA256 Hash of the input
     *
     * @param input - String to hash.
     * @param key - RSA private key.
     * @returns sha256 Hash.
     */
    rsaSha256Hash(input: string, key: string): string

    /**
     * HMAC SHA256 of the input
     *
     * @param input - String to hash.
     * @param key - secret key.
     * @returns HMAC SHA256.
     */
    hmacSha256Hash(input: string, key: string): string

    /**
     * BCrypt hash of a password
     *
     * @param password - password to hash.
     * @returns password bcrypt hash.
     */
    bcryptHash(password: string): string

    /**
     * Compare BCrypt password hash with password for a match.
     *
     * @param password - plaintext password.
     * @param hash - hashed password.
     * @returns true if hashed password and plaintext password match, false otherwise.
     */
    bcryptCompare(hash: string, password: string): boolean

    /**
     * Authenticate with Apple.
     *
     * @param token - Apple token.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateApple(token: string, username?: string, create?: boolean): AuthResult

    /**
     * Authenticate using a custom identifier.
     *
     * @param id - custom identifier.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateCustom(id: string, username?: string, create?: boolean): AuthResult

    /**
     * Authenticate using a device identifier.
     *
     * @param id - device identifier.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateDevice(id: string, username?: string, create?: boolean): AuthResult

    /**
     * Authenticate using email.
     *
     * @param email - account email.
     * @param password - account password.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateEmail(email: string, password: string, username?: string, create?: boolean): AuthResult

     /**
     * Authenticate using Facebook account.
     *
     * @param token - Facebook token.
     * @param importFriends - import FB account friends.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateFacebook(token: string, importFriends?: boolean, username?: string, create?: boolean): AuthResult

    /**
     * Authenticate using Facebook Instant Game.
     *
     * @param signedPlayerInfo - Facebook Instant Game signed player info.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateFacebookInstantGame(signedPlayerInfo: string, username?: string, create?: boolean): AuthResult

    /**
     * Authenticate using Apple Game center.
     *
     * @param playerId - Game center player ID.
     * @param bundleId - Game center bundle ID.
     * @param ts - Timestamp.
     * @param salt - Salt.
     * @param signature - Signature.
     * @param publicKeyURL - Public Key URL.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateGamecenter(
        playerId: string,
        bundleId: string,
        ts: number,
        salt: string,
        signature: string,
        publicKeyURL: string,
        username?: string,
        create?: boolean,
    ): AuthResult

    /**
     * Authenticate with Google account.
     *
     * @param token - Google token.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateGoogle(token: string, username?: string, create?: boolean): AuthResult

    /**
     * Authenticate with Steam account.
     *
     * @param token - Steam token.
     * @param username - username. If not provided a random username will be generated.
     * @param create - create user if not exists, defaults to true
     * @returns Object with authenticated user data.
     */
    authenticateSteam(token: string, username?: string, create?: boolean): AuthResult

     /**
     * Generate authentication token.
     *
     * @param userId - User ID.
     * @param exp - Token expiration, Unix epoch.
     * @param vars - Arbitrary metadata.
     * @returns Object with authenticated user data.
     */
    authenticateTokenGenerate(userId: string, exp: number, vars: {[key: string]: string}): TokenGenerateResult

    /**
     * Get account data by id.
     *
     * @param userId - User ID.
     * @returns Object with account data.
     */
    accountGetId(userId: string): Account

    /**
     * Get accounts data by ids.
     *
     * @param userIds - User IDs.
     * @returns Array containing accounts data.
     */
    accountsGetId(userIds: string[]): Account[]

    /**
     * Update user account
     *
     * @param userId - Target account.
     * @param data - Object with the data to update.
     */
    accountUpdateId(userId: string, data: UserUpdateAccount)

    /**
     * Delete user account
     *
     * @param userId - Target account.
     */
    accountDeleteId(userId: string)

    /**
     * Export user account data to JSON encoded string
     *
     * @param userId - Target account.
     */
    accountExportId(userId: string): string

    /**
     * Get user data by ids.
     *
     * @param userIds - User IDs.
     */
    usersGetId(userIds: string[]): User[]

    /**
     * Get user data by usernames.
     *
     * @param usernames - Usernames.
     */
    usersGetUsername(usernames: string[]): User[]

    /**
     * Ban a group of users by id.
     *
     * @param userIds - User IDs.
     */
    usersBanId(userIds: string[])

    /**
     * Unban a group of users by id.
     *
     * @param userIds - User IDs.
     */
    usersUnbanId(userIds: string[])

    /**
     * Link an account to Apple sign in.
     *
     * @param userID - User ID.
     * @param token - Apple sign in token.
     */
    linkApple(userID: string, token: string)

    /**
     * Link an account to a customID.
     *
     * @param userID - User ID.
     * @param customID - Custom ID.
     */
    linkCustom(userID: string, customID: string)

    /**
     * Link account to a custom device.
     *
     * @param userID - User ID.
     * @param deviceID - Device ID.
     */
    linkDevice(userID: string, deviceID: string)

    /**
     * Link account to username and password.
     *
     * @param userID - User ID.
     * @param email - Email.
     * @param password - Password.
     */
    linkEmail(userID: string, email: string, password: string)

    /**
     * Link account to Facebook.
     *
     * @param userID - User ID.
     * @param username - Facebook username.
     * @param token - Password.
     * @param importFriends - Import Facebook Friends. Defaults to true.
     */
    linkFacebook(userID: string, username: string, token: string, importFriends?: boolean)

    /**
     * Link account to Facebook Instant Games.
     *
     * @param userID - User ID.
     * @param signedPlayerInfo - Signed player info.
     */
    linkFacebookInstantGame(userID: string, signedPlayerInfo: string)

    /**
     * Link account to Apple Game Center.
     *
     * @param userID - User ID.
     * @param playerId - Game center player ID.
     * @param bundleId - Game center bundle ID.
     * @param ts - Timestamp.
     * @param salt - Salt.
     * @param signature - Signature.
     * @param publicKeyURL - Public Key URL.
     */
    linkGameCenter(
        userID: string,
        playerId: string,
        bundleId: string,
        ts: number,
        salt: string,
        signature: string,
        publicKeyURL: string,
    )

    /**
     * Unlink Apple sign in from an account.
     *
     * @param userID - User ID.
     * @param token - Apple sign in token.
     */
    unlinkApple(userID: string, token: string)

    /**
     * Unlink a customID from an account.
     *
     * @param userID - User ID.
     * @param customID - Custom ID.
     */
    unlinkCustom(userID: string, customID: string)

    /**
     * Unlink a custom device from an account.
     *
     * @param userID - User ID.
     * @param deviceID - Device ID.
     */
    unlinkDevice(userID: string, deviceID: string)

    /**
     * Unlink username and password from an account.
     *
     * @param userID - User ID.
     * @param email - Email.
     */
    unlinkEmail(userID: string, email: string)

    /**
     * Unlink Facebook from an account.
     *
     * @param userID - User ID.
     * @param token - Password.
     */
    unlinkFacebook(userID: string, token: string)

    /**
     * Unlink Facebook Instant Games from an account.
     *
     * @param userID - User ID.
     * @param signedPlayerInfo - Signed player info.
     */
    unlinkFacebookInstantGame(userID: string, signedPlayerInfo: string)

    /**
     * Unlink Apple Game Center from an account.
     *
     * @param userID - User ID.
     * @param playerId - Game center player ID.
     * @param bundleId - Game center bundle ID.
     * @param ts - Timestamp.
     * @param salt - Salt.
     * @param signature - Signature.
     * @param publicKeyURL - Public Key URL.
     */
    unlinkGameCenter(
        userID: string,
        playerId: string,
        bundleId: string,
        ts: number,
        salt: string,
        signature: string,
        publicKeyURL: string,
    )

    /**
     * Unlink Google from account.
     *
     * @param userID - User ID.
     * @param token - Google token.
     */
    unlinkGoogle(userID: string, token: string)

    /**
     * Unlink Steam from an account.
     *
     * @param userID - User ID.
     * @param token - Steam token.
     */
    unlinkSteam(userID: string, token: string)
}

/**
 * The start function for Nakama to initialize the server logic.
 */
interface InitModule {
    /**
     * Executed at server startup.
     *
     * @remarks
     * This function executed will block the start up sequence of the game server. You must use
     * care to limit the compute time of logic run in this function.
     *
     * @param ctx - The context of the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param initializer - The injector to initialize features in the game server.
     */
    (ctx: Context, logger: Logger, nk: Nakama, initializer: Initializer);
}

// ---

// The main entrypoint to the server execution.
function InitModule(ctx: Context, logger: Logger, nk: Nakama, initializer: Initializer): Error {
    initializer.registerRpc("match_create", (ctx2, logger2, nk2, payload) => {
        logger2.debug("payload: %q", payload);

        return JSON.stringify({ hello: "world!" });
    });
    logger.debug("Backend engine loaded.");
    return null;
}
