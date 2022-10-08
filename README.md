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
    social_root: String,
}
```
#### Output
```json
{
    members:Vec<Member>,
    genesis_filter: uint,
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
`path` follows the given application standard: `m/kind'/reset'/index'`

`Preferences` uses `kind` = 0
`Message` uses `kind` = 1
`Secret` uses `kind` = 2

`path` field must be managed by the user. It must be incremented for every new post to achieve forward secrecy at the `index` level.

User can use the `Preferences` type post to store their last used path, for better persistence. 

When in doubt, increment the `reset` path or always use a random nonce; to ensure forward secrecy.

#### Input
```json
{
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
    social_root: String,
    genesis_filter: uint,
}
```
#### Output
```json
{
    mine: Vec<Post>,
    others: Vec<Post>,
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
### delete_identity
```json
{
    social_root: String,
}
```
#### Output
```json
{
    status: bool,
}
```
