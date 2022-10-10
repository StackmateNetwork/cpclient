# cpclient

cpclient is a simplified ffi api interface to a cypherpost server.

It handles all the complex cryptographic tasks and post segregation for clients.


## API
Stringified JSON is used as IO. 

#### Common Error Output
```rust
struct S5Error{
    code: u32, // HTTP STATUS CODES
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
```dart
    master_root: String,
    account: int,
```
#### Output
```rust
struct SocialRoot {
    social_root: String,
}
```

### server_identity (COMPLETED)
#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
```
#### Output
```rust
struct ServerIdentity{
    kind: String, 
    name: String,
}
```

### get_members (COMPLETED)
#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
```
#### Output
```rust
struct Members{
    identities:Vec<Member>,
}
```
```rust
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
```dart
    hostname: String,
    socks5: int,
    admin_secret: String,
    kind: String,
    count: int,
```

#### Output
```rust
struct Invitation{
    invite_code: String,
}
```

### priv_user_invite (COMPLETED)

Only applicable to privileged users created by the admin.

#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
    invite_code: String,
```
The resulting `invite_code` will be a standard kind, which cannot be used to invite other users.

#### Output
```rust
struct Invitation{
    invite_code: String,
}
```

### join (COMPLETED)
#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
    username: String,
```
#### Output
```rust
struct ServerStatusResponse{
    status: bool
}
```

### get_badges
#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
    genesis_filter: int,
```
#### Output
```rust
struct AllBadges{
    badges: Vec<Badge>,
}
```
```rust
struct Badge{
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
```dart
    hostname: String,
    socks5: int,
    social_root: String, 
    to: String,
    kind: AnnouncementKind,
```
#### Output
```rust
struct ServerResponseStatus {
    status: bool,
}
```

### post

Users must keep track of the last used index to maintain forward secrecy. The server also keeps track of it, but this should only be used in case of recovery.

`to` semi-colon separated `kind:value` where kind is either "direct" where value is a pubkey OR "group" where value is a group id.

`payload`  semi-colon separated `kind:value` where kind is either "message" where value is a message OR "secret" where value is a hash.

`recipients` comma separated list of pubkeys who can view the post (for whome to make keys).
 
#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
    index: int,
    to: String,
    payload: String,
    recipients: String,
}
```
#### Output
```rust
struct SinglePost{
    post: PlainPost,
}
```

### last_index
#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
```

#### Output
```rust
struct LastIndex {
    last_index: u32,
}
```

### get_posts

#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
    genesis_filter: int,
```
#### Output
```rust
struct AllPosts{
    mine: Vec<PlainPost>,
    others: Vec<PlainPost>,
}
```
```rust
struct PlainPost{
    id: String,
    genesis: u64,
    expiry: u64,
    owner: String,
    post: Post,
}
```
```rust
struct Post{
    to: Recipient,
    payload: Payload,
    checksum: String,
    signature: String,
}
```
```rust
struct Recipient{
    kind: RecipientKind,
    value: String, //pubkey for direct, gid for group
}
```
```rust
enum RecipientKind{
    Direct,
    Group,
}
```
```rust
struct Payload{
    kind: PayloadKind,
    value: String,
}
```
```rust
enum PayloadKind{
    Message,
    Secret,
}
```

### get_single_post
Get a single post by id. To be used as notification stream provides post_ids.

#### Input
```dart
    hostname: String,
    socks5: int,
    social_root: String,
    post_id: int,
```
#### Output
```rust
struct SinglePost {
    post: PlainPost,
}
```


### leave (COMPLETED)

Removes an identity and all associated badges and posts.

```dart
{
    hostname: String,
    socks5: int,
    social_root: String,
}
```
#### Output
```rust
struct ServerStatusResponse{
    status: bool,
}
```

### NOTIFICATION STREAM

The notification stream api must be handled by the client. To help with this use the following helper functions:

#### create_stream_headers

```rust
{
    social_root: String,
}
```
#### Output
```rust
{
    pubkey: String,
    nonce: String,
    signature: String
}
```