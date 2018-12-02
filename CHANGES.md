# HashKitCXX CHANGES

This is a high-level summary of the most important changes.
For a full list of changes, see the [git commit log](https://github.com/sineang01/hashkitcxx/commits/) and pick the appropriate release branch.

## 1.0.0

*) Initial release.
*) Porting to C++11 the sha2 C library written by Olivier Gay.
*) Fixed issues when handling big files. In the complete() function an unsigned int variable containing the length in bits of the content to hash, would become 0 when the size was over a certain size. The variable has been converted to fixed 64 bits.
