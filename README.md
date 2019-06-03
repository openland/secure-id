# @openland/secure-id
`@openland/secure-id` is a library for encrypting id's from database to make them safe to use in API calls.

## How to use
Before using your library you need to create a *Shared Secret* and distributed it to every application node that is going to use this library. Using of OpenSSH to generate long random string is highly recommended. Shared Secret MUST NOT be stored in database, use configuration files or environment variables instead.
Shared Secret MUST be stored in a safe place since it could NOT be changed.

```typescript

// First you need to create a factory for IDs
// WARNING: Constructor performs heavy computations and can take up to 100ms. Always reuse factory and IDs!
let factory = new SecIDFactory('Shared Secret');

// Then declare all IDs:
let userId = factory.createId('UserEntity');

// Encrypt and decrypt
let encryptedUserId = userId.serialize(1); // == "AVljNZ9dX8I40v3xRMeVUyN9Nv"
let decryptedUserId = userId.parse(encryptedUserId); // == 1
```

## ID style
`@openland/secure-id` supports three encoding formats: `hex`, `base64` and `hashids`. Default one is `hashids`: https://hashids.org.

```typescript

let hexFactory = new SecIDFactory('Shared Secret', 'hex');
let base64Factory = new SecIDFactory('Shared Secret', 'base64');
```


## License
MIT (c) Data Makes Perfect LLC
