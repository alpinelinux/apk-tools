apk-keys(5)

# NAME

*/etc/apk/keys* - cryptographic keys trusted by apk

# DESCRIPTION

The */etc/apk/keys* directory stores RSA public keys which are trusted by apk
to verify cryptographic signatures for packages. To trust a new key, simply add
the armored public key to this directory. See *abuild-keygen*(1) for
information on generating new keys, *abuild-sign*(1) for using these keys to
sign files, and *apk-verify*(8) for verifying keys against the apk trust store.
