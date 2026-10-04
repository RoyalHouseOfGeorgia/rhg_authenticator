package update

// PinnedRequirement is the code-signing requirement every update bundle must
// satisfy (codesign --verify -R) before it is staged or applied: the app's
// bundle identifier, signed by the pinned self-signed release certificate
// (SHA-1 of the leaf certificate, the only hash the requirement language
// supports).
//
// It is requirement.txt from scripts/gen-macos-cert.sh, pasted verbatim.
// Replacing the certificate changes this value, and installed apps then reject
// every update until each user reinstalls manually (see DEVELOPER.md).
const PinnedRequirement = `identifier "ge.royalhouseofgeorgia.rhg-authenticator" and certificate leaf = H"037117d571685e21eb0b40d500a56ad103556acd"`
