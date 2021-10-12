# Password Stack for Golang

Secure password hashing for interactive logins, with versioning as your application evolves.

Allows application developers to version their password storage methods, continuing to
support them as new methods become available or keys for keyed storage need rotating.

## API

```go
import "github.com/thechriswalker/pwstack"


func main(){

    // our application wants to use Argon2id with a HMAC based secret key
    // using our inbuild pepper mechanism which uses sha3-384
    // this is the third iteration of our scheme.
    preferredHash = stack.Peppered(
        stack.DefaultArgon2idParams_2021_10(3),
        []byte("secretKey")
    )

    // but previously we had and different key, same everything else
    // version 2
    withOldKey = stack.Peppered(
        stack.DefaultArgon2idScheme_2021_10(2),
        []byte("some old key, now rotated")
    )

    // and before that we had non keyed scrypt hashes
    // version 1
    evenOlder = stack.DefaultScryptScheme_2021_10(1)

    // now lets build a stack.
    // we give each "hash" a version, so that
    // we know which hasher to use. All versions
    // should be constant/static over your application's
    // lifetime. once all hashes have migrated, you
    // can drop support for the old ones.
    pwstack, err := stack.New(
        preferredHash,
        withOldKey,
        evenOlder,
    )
    if err != nil {
        panic(err)
    }

    plaintext := "hunter2"

    hash, err := pwstack.Hash(plaintext)
    if err != nil {
        panic(err)
    }

    // save hash to DB.
    log.Println(hash)

    // later, we can check
    match, err := pwstack.Compare(plaintext, hash)
    if !match {
        // password did not match the given hash
    }
    if errors.Is(err, stack.ErrDeprecatedHash) {
        // we should regenerate the hash while we have the plaintext
        // and update in our database
    }

    // there is also a helper to combine the update function
    match, err = pwstack.CompareAndUpdate(plaintext, hash, func(newHash string) error {
        // code here to update the stored hash, with the new version.
        // only called if required.
        // a returned error will be passed to the outer return value.
        return nil
    })
}
```