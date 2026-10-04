package update

// PinnedRequirement is the code-signing requirement every update bundle must
// satisfy (codesign --verify -R) before it is staged or applied: the app's
// bundle identifier, signed by the pinned self-signed release certificate
// (SHA-1 of the leaf certificate, the only hash the requirement language
// supports).
//
// PLACEHOLDER — replace with requirement.txt from scripts/gen-macos-cert.sh
// before the first release; a zero hash matches no certificate, so updates
// fail closed.
const PinnedRequirement = `identifier "ge.royalhouseofgeorgia.rhg-authenticator" and certificate leaf = H"0000000000000000000000000000000000000000"`
