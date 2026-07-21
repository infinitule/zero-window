// Single import point for libsodium native bindings. Everything in the
// monorepo that needs sodium goes through @zw/crypto so that the native
// dependency surface stays auditable in one place.
import sodium from "sodium-native";

export default sodium;
