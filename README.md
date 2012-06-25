siphash-csharp
==============

C# Implementation of the SipHash Algorithm (Aumasson &amp; Bernstein, 2012)

* Implements KeyedHashAlgorithm, allowing for use with existing code
* Allows consumers to directly specify c and d values (defaults to c=2, d=4).  
* Instance may be reused across hashes
* Supports streaming hashes across arbitrary block sizes
* Does not require that value being hashed exist entirely in memory at any given time