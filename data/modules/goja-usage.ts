
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
 * A After Hook function definition.
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
 * Dispatcher API definition.
 */
interface Dispatcher {
    /**
     * Broadcast a message to match presences.
     *
     * @param opcode - Numeric message op code.
     * @param data - Opt. Data payload string, or nil.
     * @param presences - Opt. List of presences (a subset of match participants) to use as message targets, or nil to send to the whole match. Defaults to nil
     * @param sender - Opt. A presence to tag on the message as the 'sender', or nil.
     * @param reliable - Opt. Broadcast the message with delivery guarantees or not. Defaults to true.
     */
    broadcastMessage(opcode: number, data?: string, presences?: Presence[], sender?: Presence, reliable?: boolean);

    /**
     * Defer message broadcast to match presences.
     *
     * @param opcode - Numeric message op code.
     * @param data - Opt. Data payload string, or nil.
     * @param presences - Opt. List of presences (a subset of match participants) to use as message targets, or nil to send to the whole match. Defaults to nil
     * @param sender - Opt. A presence to tag on the message as the 'sender', or nil.
     * @param reliable - Opt. Broadcast the message with delivery guarantees or not. Defaults to true.
     */
    broadcastMessageDeferred(opcode: number, data?: string, presences?: Presence[], sender?: Presence, reliable?: boolean);

    /**
     * Kick presences from match.
     *
     * @param presences - List of presences to kick from the match.
     */
    matchKick(presences: Presence[]);

    /**
     * Update match label.
     *
     * @param label - New label for the match.
     */
    matchKick(label: string);
}

/**
 * Match Message definition
 */
interface MatchMessage {
    user_id: string;
    session_id: string;
    node_id: string;
    hidden: boolean;
    persistence: boolean;
    username: string;
    status: string;
    opcode: number;
    data: string;
    reliable: boolean;
    receive_time: number;
}

/**
 * Match handler definitions
 */
interface MatchHandler {
    match_init: MatchInitFunction;
    match_join_attempt: MatchJoinAttemptFunction;
    match_join: MatchJoinFunction;
    match_leave: MatchLeaveFunction;
    match_loop: MatchLoopFunction;
    match_terminate: MatchTerminateFunction;
}

/**
 * Match initialization function definition.
 */
interface MatchInitFunction {
    /**
     * Match initialization function definition.
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param params - Match create http request parameters.
     * @returns An object with the match state, tick rate and labels.
     */
    (ctx: Context, logger: Logger, nk: Nakama, params: Object): {state: Object, tick_rate: number, label: string};
}

/**
 * Match join attempt function definition.
 */
interface MatchJoinAttemptFunction {
    /**
     * User match join attempt function definition.
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param dispatcher - Message dispatcher APIs.
     * @param tick - Current match loop tick.
     * @param state - Current match state.
     * @param presence - Presence of user attempting to join.
     * @param metadata - Metadata object.
     * @returns object with state, acceptUser and optional rejection message if acceptUser is false.
     */
    (ctx: Context, logger: Logger, nk: Nakama, dispatcher: Dispatcher, tick: number, state: Object, presence: Presence, metadata: Object): {state: Object, accept: boolean, reject_msg: string};
}

/**
 * Match join function definition.
 */
interface MatchJoinFunction {
    /**
     * User match join function definition.
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param dispatcher - Message dispatcher APIs.
     * @param tick - Current match loop tick.
     * @param state - Current match state.
     * @param presences - List of presences.
     * @returns object with the new state of the match.
     */
    (ctx: Context, logger: Logger, dispatcher: Dispatcher, nk: Nakama, tick: number, state: Object, presences: Presence[]): {state: Object};
}

/**
 * Match leave function definition.
 */
interface MatchLeaveFunction {
    /**
     * User match leave function definition.
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param dispatcher - Message dispatcher APIs.
     * @param tick - Current match loop tick.
     * @param state - Current match state.
     * @param presences - List of presences.
     * @returns object with the new state of the match.
     */
    (ctx: Context, logger: Logger, dispatcher: Dispatcher, nk: Nakama, tick: number, state: Object, presences: Presence[]): {state: Object};
}

/**
 * Match loop function definition.
 */
interface MatchLoopFunction {
    /**
     * User match leave function definition.
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param dispatcher - Message dispatcher APIs.
     * @param tick - Current match loop tick.
     * @param state - Current match state.
     * @param messages - Received messages in the buffer.
     */
    (ctx: Context, logger: Logger, dispatcher: Dispatcher, nk: Nakama, tick: number, state: Object, messages: MatchMessage[]): {state: Object};
}

/**
 * Match terminate function definition.
 */
interface MatchTerminateFunction {
    /**
     * User match leave function definition.
     * @param ctx - The context for the execution.
     * @param logger - The server logger.
     * @param nk - The Nakama server APIs.
     * @param dispatcher - Message dispatcher APIs.
     * @param tick - Current match loop tick.
     * @param state - Current match state.
     * @param graceSeconds - Number of seconds to gracefully terminate the match. If this time elapses before the function returns the match will be forcefully terminated.
     */
    (ctx: Context, logger: Logger, dispatcher: Dispatcher, nk: Nakama, tick: number, state: Object, graceSeconds: number): {state: Object};
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
    user_id: string;
    username?: string;
    display_name?: string;
    avatar_url?: string;
    lang_tag?: string;
    location?: string;
    timezone?: string;
    metadata?: object;
}

/**
 * Stream object
 */
interface Stream {
    mode: string;
    subject: string;
    subcontext: string;
    label: string;
}

/**
 * Presence object
 */
interface Presence {
    user_id: string;
    session_id: string;
    node_id: string;
    hidden: boolean;
    persistence: boolean;
    username: string;
    status: string;
}

/**
 * Match Object
 */
interface Match {
    match_id: string;
    authoritative: boolean;
    size: number;
}

/**
 * Notification Object
 */
interface Notification {
    code: number;
    content: Object;
    persistent: boolean;
    sender: string;
    subject: string;
    userID: string;
}

/**
 * Wallet Update
 */
interface WalletUpdate {
    user_id: string;
    changeset: {[key: string]: number};
    metadata: Object;
}

/**
 * Wallet Update Result
 */
interface WalletUpdateResult {
    // Wether the value has changed from the update.
    updated: boolean;
    // The wallet value prior to the update.
    previous: number;
}

/**
 * Wallet Ledger Update Result
 */
interface WalletLedgerResult {
    id: string;
    user_ud: string;
    create_time: number;
    update_time: number;
    changeset: {[key: string]: number};
    metadata: Object;
}

/**
 * Storage Object
 */
interface StorageObject {
    key: string;
	collection: string;
	user_id: string;
	version: string;
	permission_read: number;
	permission_write: number;
	create_time: number;
	update_time: number;
	value: Object;
}

/**
 * Storage Read Request
 */
interface StorageReadRequest {
    key: string;
	collection: string;
	user_id: string;
}

/**
 * Storage Write Request
 */
interface StorageWriteRequest {
    key: string;
	collection: string;
    user_id: string;
    value: Object;
    version?: string;
    permission_read?: number;
    permission_write?: number;
}

/**
 * Storage Write Ack
 */
interface StorageWriteAck {
    key: string;
	collection: string;
    user_id: string;
    version: string;
}

/**
 * Storage Delete Request
 */
interface StorageDeleteRequest {
    key: string;
	collection: string;
    user_id?: string;
    version?: string;
}

/**
 * Leaderboard Record Entry
 */
interface LeaderBoardRecord {
    leaderboard_id: string;
	owner_id: string;
    username: string;
	score: number;
	subscore: number;
	num_score: number;
	metadata: Object;
	create_time: number;
	update_time: number;
    expiry_time: number;
}

/**
 * Leaderboard Record Entry
 */
interface Tournament {
    id: string;
    title: string;
    description: string;
    category: number;
    sort_order: 'asc' | 'desc';
    size: number;
    max_size: number;
    max_num_score: number;
    duration: number;
    start_active: number;
    end_active: number;
    can_enter: boolean;
    next_reset: string;
    metadata: Object;
    create_time: number;
    start_time: number;
    end_time: number;
}

/**
 * Group Entry
 */
interface Group {
    id: string;
    creator_id: string;
    name: string;
    description: string;
    avatar_url: string;
    lang_tag: string;
    open: boolean;
    edge_count: number;
    max_count: number;
    create_time: number;
    update_time: number;
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
     * Update user account.
     *
     * @param userId - User ID for which the information is to be updated.
     * @param displayName - Display name to be updated. Use null to not update this field.
     * @param timezone - Timezone to be updated. Use null to not update this field.
     * @param location - Location to be updated. Use null to not update this field.
     * @param language - Language to be updated. Use null to not update this field.
     * @param avatar - User's avatar URL. Use null to not update this field.
     * @param metadata - Metadata to update. Use null not to update this field.
     */
    accountUpdateId(userId: string, displayName: string, timezone: string, location: string, language: string, avatar: string, metadata: Object)

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

    /**
     * List stream presences.
     *
     * @param stream - Stream object.
     * @param includeHidden - Optional argument to include hidden presences in the list or not, default true.
     * @param includeNotHidden - Optional argument to include not hidden presences in the list or not, default true.
     * @returns List of presence objects.
     */
    streamUserList(stream: Stream, includeHidden?: boolean, includeNotHidden?: boolean): Presence[]

    /**
     * Get presence of user in a stream.
     *
     * @param userID - User ID.
     * @param sessionID - Session ID.
     * @param stream - Stream data.
     * @returns Presence object.
     */
    streamUserGet(userID: string, sessionID: string, stream: Stream): Presence

     /**
     * Add a user to a stream.
     *
     * @param userID - User ID.
     * @param sessionID - Session ID.
     * @param stream - Stream data.
     * @param hidden - Opt. If hidden no presence events are generated for the user.
     * @param persistence - Opt. By default persistence is enabled, if the stream supports it.
     * @param status - Opt. By default no status is set for the user.
     */
    streamUserJoin(userID: string, sessionID: string, stream: Stream, hidden?: boolean, persistence?: boolean, status?: string)

    /**
     * Update user status in a stream.
     *
     * @param userID - User ID.
     * @param sessionID - Session ID.
     * @param stream - Stream data.
     * @param hidden - Opt. If hidden no presence events are generated for the user.
     * @param persistence - Opt. By default persistence is enabled, if the stream supports it.
     * @param status - Opt. By default no status is set for the user.
     */
    streamUserUpdate(userID: string, sessionID: string, stream: Stream, hidden?: boolean, persistence?: boolean, status?: string)

    /**
     * Have a user leave a stream.
     *
     * @param userID - User ID.
     * @param sessionID - Session ID.
     * @param stream - Stream data.
     */
    streamUserLeave(userID: string, sessionID: string, stream: Stream)

    /**
     * Kick user from a stream.
     *
     * @param presence - User presence data.
     * @param stream - Stream data.
     */
    streamUserKick(presence: Presence, stream: Stream)

    /**
     * Count the users in a stream.
     *
     * @param stream - Stream data.
     * @returns the number of users in the stream.
     */
    streamCount(stream: Stream): number

    /**
     * Close a stream.
     *
     * @param stream - Stream data.
     * @returns the number of users in the stream.
     */
    streamClose(stream: Stream)

    /**
     * Send data to users in a stream.
     *
     * @param stream - Stream data.
     * @param data - Data string to send.
     * @param presences - Opt. List of presences in the stream to send the data to. If nil or empty, data is sent to all the users.
     * @param reliable - Opt. If data is sent with delivery guarantees. Defaults to true
     */
    streamSend(stream: Stream, data: string, presences?: Presence[], reliable?: boolean)

    /**
     * Send envelope data to users in a stream.
     *
     * @param stream - Stream data.
     * @param envelope - Envelope object. // TODO define envelope interface
     * @param presences - Opt. List of presences in the stream to send the data to. If nil or empty, data is sent to all the users.
     * @param reliable - Opt. If data is sent with delivery guarantees. Defaults to true
     */
    streamSendRaw(stream: Stream, data: string, presences?: Presence[], reliable?: boolean)

    /**
     * Disconnect session.
     *
     * @param sessionID - Session ID.
     */
    sessionDisconnect(sessionID: string)

    /**
     * Create a new match.
     *
     * @param module - Name of the module the match will run.
     * @param params - Opt. Object with the initial state of the match. // TODO define params interface
     */
    matchCreate(module: string, params: Object)

    /**
     * Get a running match info.
     *
     * @param matchID - Match ID.
     * @returns match data.
     */
    matchGet(id: string): Match

    /**
     * Find matches with filters.
     *
     * @param limit - Opt. Max number of matches to return. Defaults to 1.
     * @param authoritative - Filter authoritative or non-authoritative matches. If NULL or no value is provided, both authoritative and non-authoritative match.
     * @param label - Filter by a label. If null or no value is provided, all labels are matched.
     * @param minSize - Filter by min number of players in a match. If NULL or no value is provided, there is no lower player bound.
     * @param MaxSize - Filter by max number of players in a match. If NULL or no value is provided, there is no upper player bound.
     * @param query - Query by match properties (https://heroiclabs.com/docs/gameplay-matchmaker/#query). If no value is provided, all properties match.
     * @returns list of running game matches that match the specified filters.
     */
    matchList(id: string): Match[]

    /**
     * Send a notification.
     *
     * @param userID - User ID.
     * @param subject - Subject of the notification.
     * @param content - Key value object to send as the notification content.
     * @param code - Custom code for the notification. Must be a positive integer.
     * @param senderID - Sender ID.
     * @param persistent - A non-persistent message will only be received by a client which is currently connected to the server.
     */
    notificationSend(userID: string, subject: string, content: Object, code: number, senderID: string, persistent: boolean)

    /**
     * Update user wallet.
     *
     * @param userID - User ID.
     * @param changeset - Object with the wallet changeset data.
     * @param metadata - Opt. Metadata.
     * @param updateLedger - Opt. ??
     */
    walletUpdate(userID: string, changeset: Object, metadata?: {[key: string]: string}, updateLedger?: boolean): WalletUpdateResult

    /**
     * Update multiple user wallet.
     *
     * @param updates - Array with the wallet update objects.
     */
    walletsUpdate(updates: WalletUpdate[]): WalletUpdateResult[]

    /**
     * Update user wallet ledger.
     *
     * @param ledgerID - The ledger id.
     * @param metadata - Object with the ledger metadata to set.
     * @returns updated ledger data.
     */
    walletLedgerUpdate(ledgerID: string, metadata: Object): WalletLedgerResult

    /**
     * Update user wallet ledger.
     *
     * @param userID - User ID
     * @param limit - Opt. Maximum number of items to list. Defaults to 100.
     * @param cursor - Opt. Pagination cursor.
     * @returns Object containing an array of wallet ledger results and a cursor for the next page of results, if there is one.
     */
    walletLedgerList(user_id: string, limit?: number, cursor?: string): {items: WalletLedgerResult, cursor: string}

    /**
     * List user's storage objects from a collection.
     *
     * @param userID - User ID
     * @param collection - Storage collection.
     * @param limit - Opt. Maximum number of items to list. Defaults to 100.
     * @param cursor - Opt. Pagination cursor.
     * @returns Object containing an array of storage objects and a cursor for the next page of results, if there is one.
     */
    storageList(userID: string, collection: string, limit?: number, cursor?: string): {items: StorageObject, cursor: string}

    /**
     * Get all storage objects matching the parameters.
     *
     * @param keys - Array of storage read objects.
     * @returns Object containing an array of storage objects and a cursor for the next page of results, if there is one.
     */
    storageRead(keys: StorageReadRequest[]): StorageObject[]

    /**
     * Write storage objects.
     *
     * @param keys - Array of storage objects to write.
     * @returns List of written objects acks.
     */
    storageWrite(keys: StorageWriteRequest[]): StorageWriteAck[]

    /**
     * Delete storage objects.
     *
     * @param keys - Array of storage objects to write.
     * @returns List of written objects acks.
     */
    storageDelete(keys: StorageDeleteRequest[])

    /**
     * Update multiple entities.
     * Passing nil to any of the arguments will ignore the corresponding update.
     *
     * @param accountUpdates - Array of account updates.
     * @param storageObjectsUpdates - Array of storage objects updates.
     * @param walletUpdates - Array of wallet updates.
     * @param updateLedger - Opt. Wether if the wallet update should also update the wallet ledger. Defaults to false.
     * @returns An object with the results from wallets and storage objects updates.
     */
    multiUpdate(accountUpdates: UserUpdateAccount[], storageObjectsUpdates: StorageWriteRequest[], walletUpdates: WalletUpdate[], updateLedger?: boolean): {storage_write_acks: StorageWriteAck[], wallet_update_acks: WalletUpdateResult[]}

    /**
     * Create a new leaderboard.
     *
     * @param leaderboardID - Leaderboard id.
     * @param authoritative - Opt. Authoritative Leaderboard if true. // TODO what does this do?
     * @param sortOrder - Opt. Sort leaderboard in desc or asc order. Defauts to "desc".
     * @param operator - Opt. Score operator "best", "set" or "incr" (refer to the docs for more info). Defaults to "best".
     * @param resetSchedule - Cron string to set the periodicity of the leaderboard reset. Set as null to never reset.
     * @param metadata - Opt. metadata object.
     */
    leaderboardCreate(
        leaderboardID: string,
        authoritative: boolean,
        sortOrder?: 'desc' | 'asc',
        operator?: 'best' | 'set' | 'incr',
        resetSchedule?: null | string,
        metadata?: Object,
    )

    /**
     * Delete a leaderboard.
     *
     * @param leaderboardID - Leaderboard id.
     */
    leaderboardDelete(leaderboardID: string)

    /**
     * List records of a leaderboard.
     *
     * @param leaderboardID - Leaderboard id.
     * @param leaderboardOwners - Array of leaderboard owners.
     * @param limit - Max number of records to return.
     * @param cursor - Page cursor.
     * @param overrideExpiry - Override the time expiry of the leaderboard. (Unix epoch)
     */
    leaderboardRecordsList(leaderboardID: string, leaderboardOwners?: string[], limit?: number, cursor?: string, overrideExpiry?: number): LeaderBoardRecord[]

    /**
     * Write a new leaderboard record.
     *
     * @param leaderboardID - Leaderboard id.
     * @param ownerID - Array of leaderboard owners.
     * @param username - Username of the scorer.
     * @param score - Score.
     * @param subscore - Subscore.
     * @param metadata - Opt. metadata object.
     * @returns - The created leaderboard record.
     */
    leaderboardRecordWrite(leaderboardID: string, ownerID: string, username?: string, score?: number, subscore?: number, metadata?: Object): LeaderBoardRecord

    /**
     * Delete a leaderboard record.
     *
     * @param leaderboardID - Leaderboard id.
     * @param ownerID - Array of leaderboard owners.
     */
    leaderboardRecordDelete(leaderboardID: string, ownerID: string)

    /**
     * Create a new tournament.
     *
     * @param tournamentID - Tournament id.
     * @param sortOrder - Opt. Sort tournament in desc or asc order. Defauts to "desc".
     * @param operator - Opt. Score operator "best", "set" or "incr" (refer to the docs for more info). Defaults to "best".
     * @param duration - Opt. Duration of the tournament (unix epoch).
     * @param resetSchedule - Opt. Tournament reset schedule (cron synthax).
     * @param metadata - Opt. metadata object.
     * @param title -  Opt. Tournament title.
     * @param description - Opt. Tournament description.
     * @param category - Opt. Tournament category (1-127).
     * @param startTime - Opt. Tournament start time (unix epoch).
     * @param endTime - Opt. Tournament end time (unix epoch).
     * @param maxSize - Opt. Maximum size of participants in a tournament.
     * @param maxNumScore - Opt. Maximum submission attempts for a tournament record.
     * @param joinRequired - Opt. Whether the tournament needs to be joint before a record write is allowed.
     */
    tournamentCreate(
        tournamentID: string,
        sortOrder: 'desc' | 'asc',
        operator: 'best' | 'set' | 'incr',
        duration: number,
        resetSchedule?: string,
        metadata?: Object,
        title?: string,
        description?: string,
        category?: number,
        startTime?: number,
        endTime?: number,
        maxSize?: number,
        maxNumScore?: number,
        joinRequired?: boolean,
    )

    /**
     * Delete a tournament.
     *
     * @param tournamentID - Tournament id.
     */
    tournamentDelete(tournamentID: string)

    /**
     * Add additional score attempts to the owner's tournament record.
     *
     * @param tournamentID - Tournament id.
     * @param ownerID - Owner of the record id.
     * @param count - Attempt count to add.
     */
    tournamentAddAttempt(tournamentID: string, ownerID: string, count: number)

    /**
     * Join a tournament.
     *
     * A tournament may need to be joined before the owner can submit scores.
     *
     * @param tournamentID - Tournament id.
     * @param userID - Owner of the record id.
     * @param username - The username of the record owner.
     */
    tournamentJoin(tournamentID: string, userId: string, username: string)

    /**
     * Get a list of tournaments by id.
     *
     * @param tournamentIDs - Tournament ids.
     * @returns The tournament data for the given ids.
     */
    tournamentsGetId(tournamentIds: string[]): Tournament[]

    /**
     * Get a list of tournaments by id.
     *
     * @param categoryStart - Filter tournament with categories greater or equal than this value.
     * @param categoryEnd - Filter tournament with categories equal or less than this value.
     * @param startTime - Filter tournament with that start after this time.
     * @param endTime - Filter tournament with that end before this time.
     * @param limit - Return only the required number of tournament denoted by this limit value.
     * @param cursor - Cursor to paginate to the next result set. If this is empty/null there is no further results.
     * @returns The tournament data for the given ids.
     */
    tournamentList(categoryStart?: number, categoryEnd?: number, startTime?: number, endTime?: number, limit?: number, cursor?: string): Tournament[]

    /**
     * Submit a score and optional subscore to a tournament leaderboard.
     *
     * @param id - The unique identifier for the leaderboard to submit to. Mandatory field.
     * @param ownerID - The owner of this score submission. Mandatory field.
     * @param username - Opt. The owner username of this score submission, if it's a user.
     * @param score - Opt. The score to submit. Optional in Lua. Default 0.
     * @param subscore - Opt. A secondary subscore parameter for the submission. Optional in Lua. Default 0.
     * @param metadata - Opt. The metadata you want associated to this submission.
     * @returns The tournament data for the given ids.
     */
    tournamentRecordWrite(id: string, ownerID: string, username?: string, score?: number, subscore?: number, metadata?: Object)

    /**
     * Fetch the list of tournament records around the owner.
     *
     * @param id - The unique identifier for the leaderboard to submit to. Mandatory field.
     * @param ownerID - The owner of this score submission. Mandatory field.
     * @param limit - Opt. The owner username of this score submission, if it's a user.
     * @param expiry - Opt. Expiry Unix epoch.
     * @returns The tournament data for the given ids.
     */
    tournamentRecordsHaystack(id: string, ownerID: string, limit?: number, expiry?: number): Tournament[]

    /**
     * Fetch one or more groups by their ID.
     *
     * @param groupIDs - A set of strings of the ID for the groups to get.
     * @returns An array of group objects.
     */
    groupsGetId(groupIDs: string[]): Group[]

    /**
     * Fetch one or more groups by their ID.
     *
     * @param userID - The user ID to be associcated as the group superadmin.
     * @param name - Group name, must be set and unique.
     * @param creatorID - The user ID to be associcated as creator. If not set, system user will be set.
     * @param lang - Opt. Group language. Will default to 'en'.
     * @param description - Opt. Group description, can be left empty.
     * @param avatarURL - Opt. URL to the group avatar, can be left empty.
     * @param open - Opt. Whether the group is for anyone to join, or members will need to send invitations to join. Defaults to false.
     * @param metadata - Opt. Custom information to store for this group.
     * @param limit - Opt. Maximum number of members to have in the group. Defaults to 100.
     * @returns An array of group objects.
     */
    groupsCreate(userID: string, name: string, creatorID: string, lang?: string, description?: string, avatarURL?: string, open?: boolean, metadata?: Object, limit?: number): Group[]

    /**
     * Update a group with various configuration settings.
     * The group which is updated can change some or all of its fields.
     *
     * @param groupID - The group ID to update.
     * @param name - Group name, use nil to not update.
     * @param creatorID - The user ID to be associcated as creator, use nil to not update.
     * @param lang - Group language, use nil to not update.
     * @param description - Group description, use nil to not update.
     * @param avatarURL - URL to the group avatar, use nil to not update.
     * @param open - Whether the group is for anyone to join or not. Use nil to not update.
     * @param metadata - Custom information to store for this group. Use nil to not update.
     * @param limit - Maximum number of members to have in the group. Use nil if field is not being updated.
     */
    groupUpdate(userID: string, name: string, creatorID: string, lang: string, description: string, avatarURL: string, open: boolean, metadata: Object, limit: number)

    /**
     * Delete a group.
     *
     * @param groupID - The group ID to update.
     */
    groupDelete(groupID: string)

    /**
     * Kick users from a group.
     *
     * @param groupID - The group ID to update.
     * @param userIDs - Array of user IDs to be kicked from the group.
     */
    groupUsersKick(userID: string, userIDs: string[])

    /**
     * List all members, admins and superadmins which belong to a group.
     * This also list incoming join requests too.
     *
     * @param groupID - The group ID to update.
     * @param limit - Opt. Max number of returned results. Defaults to 100.
     * @param state - Opt. Filter users by their group state (0: Superadmin, 1: Admin, 2: Member, 3: Requested to join). Use nil or undefined to return all states.
     * @param cursor - Opt. A cursor used to fetch the next page when applicable.
     * @returns A list of group members.
     */
    groupUsersList(userID: string, limit?: number, state?: number, cursor?: string): {group_users: [{user: User, state: number}, cursor: string | null]}

    /**
     * Register a match handler.
     *
     * @param name - Identifier of the match handler.
     * @param functions - Object containing the match handler functions.
     */
    registerMatch(name: string, functions: MatchHandler);
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
