package collate

// ownTimensOffset is the collator's own CLOCK_BOOTTIME namespace offset,
// behind a seam because the platform implementation is a CONSTANT ZERO
// off Linux — so a test that compared against zero and a test that
// compared against our own offset passed identically on a development
// machine, and the difference only matters on a collator that is itself
// inside a namespace. Substituting this is how the comparison gets
// tested rather than assumed.
var ownTimensOffset = timensOffset
