       usicrypt, a unified simple interface crypto library wrapper

                        (c) 2017 Andreas Steinmetz

-------------------------------------------------------------------------


Its not about reinventing the wheel. Its about reinventing the wheel nut.
=========================================================================

This code is supposed to ease the tedious work of analyzing and
implementing the different crypto library APIs which in some
cases tend to be very sensitive to proper call sequences.

A common functional subset of the supported crypto libraries is
provided and this code fills in gaps where crypto libraries do not
support some cryptographic modes to allow easy switching of the used
backend crypto library.


Short Overview:
===============

Libraries:               Libgcrypt, LibreSSL, mbedTLS, Nettle, OpenSSL, wolfSSL
Public Key Cryptography: RSA, DH, EC, x25519
RSA Padding:             v1.5, PSS, OAEP
Included DH Parameters:  rfc5114-1024-160, rfc5114-2048-224, rfc5114-2048-256
Elliptic Curves(*):      brainpoolP512r1, brainpoolP384r1, brainpoolP256r1,
                         secp521r1, secp384r1, secp256r1
Symmetric Ciphers:       AES, Camellia, ChaCha20
Standard Cipher Modes:   ECB, CBC, CTS, CFB, CFB8, OFB, CTR, XTS, ESSIV
AEAD Cipher modes:       GCM, CCM, Poly1305
Digests:                 SHA1, SHA256, SHA384, SHA512, HMAC, CMAC
Key Derivation:          PBKDF2, HKDF
Other:                   Base64 Encode/Decode, ASN.1/DER Export/Import, LFSR,
                         Private Key PBES2 Encrypt/Decrypt, DER/PEM Conversion

(*) Note: the curves starting with "secp" contain NSA defined parameters
    of undisclosed origin and should thus be considered weak. If in doubt
    and when possible these curves should not be used.


One of the main goals of this code is to assert binary compatability
of keys used for public key cryptography. Exporting a public or
private key via this code from one library will guarantee successful
import via this code into another library.

The API is kept simple and will for sure not suit every purpose.
OTOH this allows for easy use without loads of parameter lookups.

This code is not intended as a substitute for a lack of cryptographic
knowledge.


License:
========

Any OSI approved license of your choice applies, see the file LICENSE
for details. For ED25519 please see github-orlp-ed25519/license.txt,
if this library is in use (see table below).


Usage:
======

Being a small compatability layer for a user selected target library
it does not make sense to provide a shared library. Switching
between different target libraries is a compile time option.

Include usicrypt.h in your code. Adapt the Makefile to build for the
target library of your choice and to remove code not required.
Run make and then link against libusicrypt.a (position dependent code)
or libusicrypt-pic.a (position independent code).

Note that usicrypt is only tested on Linux x86\_64 using gcc, though
code for other platforms is included on a best effort base
(never compiled or tested).


Implementation Overview:
========================

|                         |OpenSSL|LibreSSL|mbedTLS|wolfSSL|Libgcrypt|Nettle|
| ----------------------- | ----- | ------ | ----- | ----- | ------- | ---- |
|                         |1.0.2k/|2.4.5/  |2.4.2/ |3.10.2/|         |      |
|                         |1.1.0e |2.5.3   |2.12.0 |3.15.0 |1.7.6    |3.3   |
| ----------------------- | ----- | ------ | ----- | ----- | ------- | ---- |
|Random Numbers           |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|SHA1                     |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|SHA256                   |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|SHA384                   |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|SHA512                   |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|HMAC/SHA1                |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|HMAC/SHA256              |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|HMAC/SHA384              |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|HMAC/SHA512              |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|PBKDF2/SHA1              |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|PBKDF2/SHA256            |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|PBKDF2/SHA384            |  x/x  |  x/x   |  x/x  |  o/o  |    x    |  x   |
|PBKDF2/SHA512            |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|HKDF/SHA1                |  o/x  |  o/o   |  o/x  |  x/x  |    o    |  o   |
|HKDF/SHA256              |  o/x  |  o/o   |  o/x  |  x/x  |    o    |  o   |
|HKDF/SHA384              |  o/x  |  o/o   |  o/x  |  x/x  |    o    |  o   |
|HKDF/SHA512              |  o/x  |  o/o   |  o/x  |  x/x  |    o    |  o   |
|Base64 Encode/Decode     |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  x   |
|RSA Generate             |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  x   |
|RSA Export/Import        |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  o   |
|RSA Sign/Verify/SHA1     |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  x   |
|RSA Sign/Verify/SHA256   |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  x   |
|RSA Sign/Verify/SHA384   |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  x   |
|RSA Sign/Verify/SHA512   |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  x   |
|RSASSA-PSS/SHA1          |  x/x  |  x/x   |  x/x  |  -/-B |    o    |  o   |
|RSASSA-PSS/SHA256        |  x/x  |  x/x   |  x/x  |  -/-B |    o    |  o   |
|RSASSA-PSS/SHA384        |  x/x  |  x/x   |  x/x  |  -/-B |    o    |  o   |
|RSASSA-PSS/SHA512        |  x/x  |  x/x   |  x/x  |  -/-B |    o    |  o   |
|RSA Encrypt/Decrypt      |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  x   |
|RSAES-OAEP/SHA1          |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  o   |
|RSAES-OAEP/SHA256        |  x/x  |  o/o   |  x/x  |  x/x  |    o    |  o   |
|RSAES-OAEP/SHA384        |  x/x  |  o/o   |  x/x  |  x/x  |    o    |  o   |
|RSAES-OAEP/SHA512        |  x/x  |  o/o   |  x/x  |  x/x  |    o    |  o   |
|DH Generate              |  x/x  |  x/x   |  x/x  |  -/o  |    o    |  o   |
|DH Key Agreement         |  x/x  |  x/x   |  x/x  |  x/x! |    o    |  o   |
|EC Generate              |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  ob  |
|EC Export/Import         |  x/x  |  x/x   |  x/x  | x!/x  |    o    |  ob  |
|ECDH Key Agreement       |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  ob  |
|ECDSA/SHA1               |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  ob  |
|ECDSA/SHA256             |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  ob  |
|ECDSA/SHA384             |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  ob  |
|ECDSA/SHA512             |  x/x  |  x/x   |  x/x  |  x/x  |    o    |  ob  |
|X25519 Generate          |  -/x  |  -/x   |  -/x  |  x/x  |    o    |  o   |
|X25519 Export/Import     |  -/x  |  -/o   |  -/o  |  o/o  |    o    |  o   |
|X25519 Key Agreement     |  -/x  |  -/x   |  -/x  |  x/x  |    o    |  o   |
|ED25519 Generate         |  e/e  |  e/e   |  e/e  |  e/e  |    e    |  e   |
|ED25519 Eport/Import     |  e/e  |  e/e   |  e/e  |  e/e  |    e    |  e   |
|ED25519 Sign/Verify      |  e/e  |  e/e   |  e/e  |  e/e  |    e    |  e   |
|AES ECB                  |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|AES CBC                  |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|AES CTS                  |  x/x  |  x/x   |  o/o  |  o/o  |    x    |  o   |
|AES CFB                  |  x/x  |  x/x   |  x/x  |  o/o  |    x    |  o   |
|AES CFB8                 |  x/x  |  x/x   |  x/x  |  o/o  |    o    |  o   |
|AES OFB                  |  x/x  |  x/x   |  o/o  |  o/o  |    x    |  o   |
|AES CTR                  |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  o!  |
|AES XTS                  |  x/x  |  x/x   |  o/o  |  o/o  |    o    |  o   |
|AES CBC/ESSIV/SHA256     |  o/o  |  o/o   |  o/o  |  o/o  |    o    |  o   |
|AES GCM                  |  x/x  |  x/x   |  x/x  | x!/xm |    x    |  x!  |
|AES CCM                  |  x/x  | x!/x!  |  x/x  |  x/x  |    x    |  x   |
|AES CMAC                 |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  o   |
|ChaCha20/Poly1305        |  -/x  |  x/x   |  -/x  |  x/x  |    x    |  x   |
|ChaCha20                 |  -/x  |  x/x   |  -/x  | x!/x! |    x    |  x!  |
|Camellia ECB             |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|Camellia CBC             |  x/x  |  x/x   |  x/x  |  x/x  |    x    |  x   |
|Camellia CTS             |  x/x  |  x/x   |  o/o  |  o/o  |    x    |  o   |
|Camellia CFB             |  x/x  |  x/x   |  x/x  |  o/o  |    x    |  o   |
|Camellia CFB8            |  x/x  |  x/x   |  o/o  |  o/o  |    o    |  o   |
|Camellia OFB             |  x/x  |  x/x   |  o/o  |  o/o  |    x    |  o   |
|Camellia CTR             |  x/x  |  x/x   |  x/x  |  o/o  |    x    |  o!  |
|Camellia XTS             |  o/o  |  o/o   |  o/o  |  o/o  |    o    |  o   |
|Camellia CBC/ESSIV/SHA256|  o/o  |  o/o   |  o/o  |  o/o  |    o    |  o   |
|Camellia CMAC            |  x/x  |  x/x   |  o/o  |  o/o  |    x    |  o   |
| ----------------------- | ----- | ------ | ----- | ----- | ------- | ---- |

x = native support
o = available, no native support
- = not available
! = bug workaround included
b = Brainpool curves not available
m = tag size minimum is 12
B = broken implementation, no interoperability and thus not usable
e = currently uses implementation from https://github.com/orlp/ed25519,
    OpenSSL starting with 1.1.1 uses native implementation
    Nettle starting with 3.4 uses native implementation

For details see the file usicrypt.h which includes all function prototypes
as well as parameter documentation.

Be aware that functionality not natively provided by the target library
but through this wrapper library is neither tuned for host nor cpu.
The required optimizations are the job of the target library and
function emulation through this wrapper is just a workaround.

OpenSSL Note:
-------------
As always with OpenSSL reading the header files is often more efficient
than looking for missing man pages or man pages with wrong information.

LibreSSL Note:
--------------
LibreSSL is missing RSA\_padding\_add\_PKCS1\_OAEP\_mgf1() as well as
RSA\_padding\_check\_PKCS1\_OAEP\_mgf1() which makes it impossible to
use a message digest other than SHA1 natively for OAEP padding.
The ChaCha20/Poly1305 AEAD interface is horrible. The tag is
written to/read from the end of the encrypted data, thus intermediate
copies are required which will certainly kill the processing speed.
Furthermore it does not support PRF setting for PBES2 which is
totally broken, try to find the '-v2prf' option for the PKCS8 tool...
And, well, the X25519 private key value is broken purposely which
can be an attack vector in detecting which library is in use.
In addition the necessary X25519 public from private function
is missing from the headers though it is not declared static.
LibreSSL is broken with regard to ED25519 as keys in portable format
can't be loaded (RFC8410, anybody?).
In general I did see a few locations where LibreSSL leaks memory
when a function fails so there's probably quite some more similar
problems.
All in all it looks as too many people with no real knowledge of
what they are doing with regards to crypto do modify this library,
thus I'm personally quite reluctant to consider its usage.

mbedTLS Note:
-------------
The missing functionality is planned by the target library developers,
though there in no arrival date set.
For CCM mode the length of the additional data is restricted to a
maximum of 0xff00 bytes.
For whatever reason ED25519 is missing out and the developers seem to be
reluctant to accept patches.

wolfSSL Note:
-------------
Using this target library has to be taken with a grain of salt. It does
not seem to receive too much testing as it exhibits unexpected bugs.
One should in particular be wary of malformed data being imported.
A nice example is the import of DH parameters with a missing final
byte which first leads to incomplete data initialization which later
on results in a segfault.
Though there is a bignum header, none of the bignum functions are
exported from the target library. Due to this fact neither DH
parameter generation nor RSASSA-PSS operation can be emulated.
A later revicion of thil library remedies the bignum export problem
and implements RSASSA-PSS, but the RSASSA-PSS implementation is broken
due to artificial limitiations which prevent interoperability.
This target library doesn't support more than 4096 bit keys for
RSA in general.
There is no way to add seed to the random number generator of the
target library.

Libgcrypt Note:
---------------
As fine as the symmetric cipher API is, the public key API is an esoteric
reminiscence to Lisp coded as unreadable gibberish with no usable
specification whatsoever. It's no wonder that Libgcrypt is not in
wide use. Adding an ASN.1/DER based interface is what is required for
real world use. To add to the problem, all required support routines
e.g. for padding are not exported and only available through the
public key mess and thus out of reach. The only solution here was
to use the low level mpi interface and from there on to reinvent the
wheel from scratch. This, however, causes another problem as
Libgcrypt offers no API for blinding, thus private key operations
are not protected against timing and similar attacks.
And, yes, the mpi interface of Libgcrypt is nearly as slow as a dead
horse and the prime generator is, well, worse than that and simply
not usable at all.

Nettle Note:
------------
Unfortunately Nettle does not support the Brainpool curves and I do not
trust the NIST curves.  If you don't understand why, search the web for
"dual ec drbg fiasco". Hopefully a future release will change this.
Furthermore Nettle only has a low to medium level interface for public
key processing with no real import/export functionality so quite
some wrapping is required. The primality checking did need a little
speed tuning though the GMP primality check has the final word.


Libraries not supported:
========================

The following list of libraries is most probably incomplete. It is
just a list of crypto libraries I came across and some reasoning
why I did chose not to include support.


BoringSSL:

A Google initiated OpenSSL fork documented as not to be used due to
no API guarantees.


Botan:

Though Botan is a C++ library it provides a C89 API, basically for
usage with the Python bindings. Unfortunately this API is rather
incomplete, e.g. it provides only ECB mode and there seems to be no
way to set the tag size for AEAD cipher modes. Until these (and
probably more) deficiencies are resolved there is no feasible
way to support this library.


cryptlib:

I didn't get further than the FAQ on the cryptlib site. The mentality
expressed there was enough skip further investigation.


Crypto++:

Unfortunately Crypto++ has only a C++ API and thus inherits all the
associated problems like ever changing compiler ABIs. C++ is nice for
GUI usage but not for performance or small footprints. I'll leave
Crypto++ to C++ projects.


GnuTLS:

GnuTLS relies on Nettle for low level functionality which is included.


MatrixSSL:

Though interesting, MatrixSSL is missing too much functionality to be
of any use beyond IoT. It is certainly too incomplete to be included here.


NSS:

It seems that NSS is for Mozilla use only and doesn't provide any
usable low level interface. The documentation is incomplete at best.
Furthermore it is another library missing out the Brainpool curves.


S2n:

S2n depends on OpenSSL for low level functionality which is included.

