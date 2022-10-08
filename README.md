# cpclient

cpclient is a simplified ffi api interface to a cypherpost server.

It handles all the complex cryptographic tasks and post segregation for clients.


## API
Stringified JSON is used as IO. 

#### Common Error Output
```json
{
    code: uint, // HTTP STATUS CODES
    message: String
}
```

#### Genesis Filter
`genesis_filter` is a common field among calls that return large vector of objects.
They can be filtered by providing this field, which will only return entries made after a certain timestamp. Default is set to 0 if no value is passed.

### create_social_root
#### Input
```json
{
    root_xprv: String,
}
```
#### Output
```json
{
    social_root: String,
    path: String,
}
```

### get_server_identity
#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
}
```
#### Output
```json
{
    name: String,
    pubkey: String,
}
```

### register
#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    username: String,
}
```
#### Output
```json
{
    status: bool
}
```

### user_invite
Only applicable to privileged users created by the admin.

#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    invite_code: String,
}
```
The resulting `invite_code` will be a standard kind, which cannot be used to invite other users.

#### Output
```json
{
    invite_code: String,
}
```

### get_members
#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    genesis_filter: uint,
}
```
#### Output
```json
{
    members:Vec<Member>,
}
```
```json
Member{
    username: String,
    pubkey: String,
}
```

### get_badges
#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    genesis_filter: uint,
}
```
#### Output
```json
{
    badges: Vec<Badge>,
}
```
```json
Badge{
    genesis: String,
    kind: AnnouncementKind,
    by: String,
    to : String,
    nonce: String,
    signature: String,
    hash: String,
}
```
```enum
AnnouncementKind{
    "Trust",
    "Scam",
}
```

### give_badge
#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String, 
    to: String,
    kind: AnnouncementKind,
}
```
#### Output
```json
{
    status: bool,
}
```

### create_post
`path` follows the given application standard: `m/kind'/reset'/reset'/index'`

`Preferences` uses `kind` = 0
`Message` uses `kind` = 1
`Secret` uses `kind` = 2
`Xpub` uses `kind` = 3

`path` field must be managed by the user. It must be incremented for every new post to achieve forward secrecy at the `index` level.

User can use the `Preferences` type post to store their last used path, for better persistence. 

When in doubt, increment the `reset` path or always use a random nonce; to ensure forward secrecy.

#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    to: String,
    kind: PayloadKind,
    message: String,
    path: String,
}
```
```enum
PayloadKind{
  "Preferences",
  "Message",
  "Secret",
}
```
#### Output
```json
{
    post_id: String,
}
```

### create_post_keys
Use the same `path` value as the post made. This is required to ensure recipients recieve the correct decryption key.

```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    path: String,
    post_id: String,
    recipients: Vec<String>,
}
```
#### Output
```json
{
    status: bool,
}
```

### get_posts

#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    genesis_filter: uint,
}
```
#### Output
```json
{
    mine: Vec<PlainPost>,
    others: Vec<PlainPost>,
}
```
```json
PlainPost{
    id: String,
    genesis: u64,
    expiry: u64,
    owner: String,
    post: Post,
}
```
```json
Post{
    to: String,
    payload: Payload,
    checksum: String,
    signature: String,
}
```
```json
Payload{
    kind: PayloadKind,
    value: String | Preferences,
}
```
```json
Preferences{
    last_path: String,
    muted: Vec<String>,
}
```

### get_single_post
Get a single post by id. To be used as notification stream provides post_ids.

#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    post_id: uint,
}
```
#### Output
```json
{
    post: PlainPost,
}
```

### delete_identity

Removes an identity and all associated badges and posts.

```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
}
```
#### Output
```json
{
    status: bool,
}
```

### NOTIFICATION STREAM

The notification stream api must be handled by the client. To help with this use the following helper functions:

#### create_stream_headers

```json
{
    social_root: String,
}
```
#### Output
```json
{
    pubkey: String,
    nonce: String,
    signature: String
}
```