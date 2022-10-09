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

#### socks5
Use a socks5 port to a local tor instance. Use 0 if communicating over clearnet.

### FUNCTIONS

### create_social_root (COMPLETED)
#### Input
```json
{
    master_root: String,
    account: uint
}
```
#### Output
```json
{
    social_root: String,
}
```

### server_identity (COMPLETED)
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
    kind: String, 
    name: String,
}
```

### get_members (COMPLETED)
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
    members:Vec<Member>,
}
```
```json
Member {
    username: String,
    pubkey: String,
}
```

### admin_invite (COMPLETED)
Only applicable for an admin with a secret.

kind must be either "priv/privileged", all other string values will default to "standard".

count sets how many users a privileged user can invite. Use 0 for standard invitations.

#### Input
```json
{
    hostname: String,
    socks5: uint,
    admin_secret: String,
    kind: String,
    count: usize,
}
```

#### Output
```json
{
    invite_code: String,
}
```

### priv_user_invite (COMPLETED)

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

### join (COMPLETED)
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

Users must keep track of the last used index to maintain forward secrecy. The server also keeps track of it, but this should only be used in case of recovery.

#### Input
```json
{
    hostname: String,
    socks5: uint,
    social_root: String,
    to: String,
    kind: PayloadKind,
    message: String,
    index: uint,
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

### last_index
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
    last_index: uint,
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


### leave (COMPLETED)

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