#show regex("TODO:.+") : (t) => {
  set text(red, weight: "bold")
  box(stroke: red + 1pt, width: 100%, inset: 1em, t)
}

#show terms: (t) => {
  for c in t.children {
    if c.term.children.len() == 3 {
      [#c.term.children.at(0): #t.separator #c.term.children.at(2).  #t.separator #c.description]
    } else {
      [#c.term. #t.separator #c.description]
    }
    linebreak()
  }
}

#let pds(pds: array, separator: h(.6em, weak: true)) = {
  for def in pds {
    pd(def.name, def.vis,def.description, separator)
  }
}
#let pd(name, vis, description, separator: h(.6em, weak: true)) = {
  [#raw(name): #vis. #separator #description #linebreak()]
}
#set ref(supplement: (s) => {
  let b = lower(s.body.text)
  if b.starts-with("appendix") {
      let appendix_name = b.split(" ").slice(1).at(0, default: "")
      [Appendix]
  } else {
    s.supplement
  }
})

#let blockContent = (t) => {
  set text(font: "DM Mono")
  let breakableContent = (t) => {
    layout(l => {
      let size = measure(t)
      let blocks = size.width / l.width
      if blocks <= 0 {
        t
      } else {
        let l = t.len()
        let blockSize = calc.ceil(l / blocks)
        let currentOffset = 0
        for b in range(0, calc.ceil(blocks)) {
          if (b +1 )*blockSize > l {
            text(t.slice(b*blockSize))
          } else {
            text(t.slice(b * blockSize, count:blockSize))
          }
          linebreak()
        }
      }
    })
  }
  breakableContent(t)
}

#title("SD-JWT with Commitments DRAFT")


= Abstract
In order to allow zero knowledge proofs on attributes within SD-JWTs, the hash algorithm definition is extended to allow the usage of commitment schemes. With commitment schemes, we can for example use simple sigma protocols to derive proofs about age, or to bind various VCs without revealing the actual properties (e.g. when using claim based binding for bridging).

#set heading(numbering: "1.")
= Introduction

There are various use cases where selective disclosure alone is not enough to secure privacy, or is too restricted for arbitrary use cases. A good example is age verification, where the current state of the art is to include multiple boolean flags based on the age during issuance. This has obvious drawbacks, as for example a person whose age reaches a threshold needs a new credential (as the boolean flag is fixed in the signed JWT-part). With this draft we could use a simple sigma protocol to proof "older than" for any threshold.

When using batch issuance to reduce link-ability (as currently used signature schemes don't allow for rerandomization), there needs to be a way of refreshing batches. In the current process this is only possible in redisclosing all personal data to the issuing party. In this draft we sketch a method in @appendix_c on how rerandomization of a VC can be done without revealing attributes inside the SD-JWT by adding a new blinding factor to the present commitments.

== Hash Function Claim
The #link("https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-22.html#name-hash-function-claim")[`_sd_alg`] of the SD-JWT _MUST_ be one of the list members in #ref(<appendix_a>). If `_sd_alg` is one of the values in that list, the SD-JWT _MUST_ add a `_sd_alg_param` value containing the required parameters for the commitment scheme.

=== Commitment Scheme specification
The `_sd_alg_param` contains the following fields:

/ `commitment_scheme` REQUIRED: The commitment scheme to use. In @appendix_a the parameters for commitment schemes defined in this specification are given.
=== Commitment Linking
For zero knowledge proofs, a unique linking of attributes to commitments needs to be given. As such, if `_sd_alg` is one of the elements in @appendix_a the top level object needs a map of attribute names to indices in the `_sd` array. This object itself can be selectively disclosable to not reveal more information than necessary:

TODO: Explain exactly how this works for deeply nested structures

/ `com_link` OPTIONAL: A map of attribute name to index in the `_sd` object. This map needs to be present if commitments in `_sd` of this level of disclosures is needed.

== Keybinding JWT
TODO: Can we have ZKPs without key binding? If so how? 

The keybinding JWT is extended with the following fields:

/ `zk_proofs` OPTIONAL: An array of `ZkpProof` structs containing zero knowledge proofs over the respective inputs.

=== ZkProof
The `ZkProof` struct contains the values required to verify the zero knowledge proof on the properties:

TODO: should we allow random linear equations, and if so how does this impact the serialization mechanism. 

/ `inputs` REQUIRED: An array of `public` and `private` inputs. Public input means a revealed value, such as a age threshold. Private inputs are for example commitments from other credentials that are not revealed but used within the zero knowledge proof
/ `system` REQUIRED: Array of length of `input` variables, specifying the _linear_ equation that should be statisfied.
/ `context` REQUIRED: Byte-Array containing the relevant proof transcript bytes used for the Fiat-Shamir transform.
/ `proof` REQUIRED: The proof value that can be verified.
/ `proof_type` REQUIRED: A proof type specifying how to deserialize `proof`.

==== equality_proof
An equality proof is serialized as bytes (each scalar and RistrettoPoint has 32 bytes), where `com1` and `com2` are the randomized commitments from stage one of the sigma protocol:

```rs
struct EqualityProof {
    s1: Scalar,
    r1: Scalar,
    s2: Scalar,
    r2: Scalar,
    com1: RistrettoPoint,
    com2: RistrettoPoint,
}
```


==== Public Inputs
Public inputs are clear text values that are lifted into the scalar field of the respective scheme. Requirements and algorithms to do so are defined in the respective commitment schemes.

/ `public_value` OPTIONAL: JSON value that can be lifted into the scalar field. Provided as plaintext.

==== Private Inputs
Private inputs are for example commitments from other credentials for which an equality should be proven. Those are already byte representations of elements of the respective group/ring of the commitment scheme.

/ `path` REQUIRED: ClaimsPointer to `com_link` or array entry for the relevant commitment
/ `value` REQUIRED: The base64-url-safe encoded commitment used in the proof.


#counter(heading).update(0)
#set heading(numbering: "A.1")
#show heading : (h) => {
  if h.level == 1 {
    [Appendix #counter(heading).display()]
  } else {
    h
  }
}
= Appendix A <appendix_a>
== List of Commitment Schemes
- ec_pedersen

== ec_pedersen
=== Parameters
When using the `ec_pedersen` format the following parameters are used:

/ `public_params` REQUIRED: Object containing the generator used for the value ($g$) and the blinding ($h$)
/ `crv` REQUIRED: Curve used for the Pedersen commitment.

=== Hashing
To produce commitments that can be used, number types should be converted to values on the scalar field, and any other type should be converted using `hash_to_curve` algorithm. For nested objects the JCS (#link("https://www.rfc-editor.org/rfc/rfc8785.html")) *MUST* be used. The first value of the disclosures array MUST be used as the blinding, and the attribute name MUST be added to the proof transcript.

TODO: Is there a better way to handle non numerical values? E.g. lexicographical representation of strings to allow ordering?

TODO:  Do we need to consider too big numerical values? 

TODO: How are floating point numbers encoded? Fixed precision and then using integers ("multiply out" the decimals?)

= Appendix B <appendix_b>

This Appendix goes over a ficticious example of presenting a Diploma, which is not bound to a specific user hold key material, together with an identity statement, which is device (aka user) bound. Normally, to have confidence that both were issued to the same person, we would need to disclose various properties and show equality between them (as the by default used sha hash does not allow for ZKP). 

Here we present both credentials, but only disclose the subject and the grade of the diploma, while providing a zero knowledge proof of equality between multiple different attributes.

== Test Vectors

=== Identity Card
==== Issuer Verification Key
```json
{
  "kty":"EC",
  "crv":"P-256",
  "x":"N3g_o1SqMpLQMqSdyGbG9nKO1fWUBBny-h-xxlFQlFk",
  "y":"5P7RM7ul-bCrTfcnkWrBGKgwfdOfG7RFwhNay1kvLu8"
}
```
==== Holder Private Key
```json
{
  "kty":"EC",
  "crv":"P-256",
  "x":"Oq1azTI-nfXRjxeoxqwktbSayE7Sd-2S0kp2MdCXdJM",
  "y":"Xz4eqZG6bq017tCtqsx97KiJzgLzbSQvOzQJBFasXKE",
  "d":"dbUsHxvpAb_D26ok8T2D5EugxWfUu0faPU9ueYhc56k"
}
```
==== Identity Card Claims
```json
{
  "sub": "user_42",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "phone_number_verified": true,
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "birthdate": 19400101,
  "updated_at": 1570000000,
  "nationalities": [
    "US",
    "DE"
  ]
}
```
==== Identity Card SD-Jwt
#blockContent("eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMyJ9.eyJzdWIiOiJ1c2VyXzQyIiwidXBkYXRlZF9hdCI6MTU3MDAwMDAwMCwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ik9xMWF6VEktbmZYUmp4ZW94cXdrdGJTYXlFN1NkLTJTMGtwMk1kQ1hkSk0iLCJ5IjoiWHo0ZXFaRzZicTAxN3RDdHFzeDk3S2lKemdMemJTUXZPelFKQkZhc1hLRSJ9fSwiX3NkIjpbImpsLXh6a0ZlQUhjeHloTkFwR1dHQkxlZHhmamhabWtpcTRmank1VEpQRkUiLCJHRFV1OWtmUWxISVV5bXhOaEdQZEhLeXBQWUUwY3ZURmFuekcxZHduUkJJIiwiWkVRT0NZMEhYNC0yZzhvU2tSN1lfV204NnFVVU9sZDNBOFFTT1k4U0FUbyIsImVOd0F4WnQ3UHhVMVQxbmhPYlhTbkRMU2s3MXk3Y2pfakNHcDlYSDZTUTQiLCI0Z0tkSGZCclFXUWdZRzdDT1hWMUl6SThBeDlrOE5XQ0xnUzBYSFFFRWt3IiwiZG9VZFRRM1pJZ25YODlacUlzLWk4MWNiRnZtOGJrSERjUU9heTZ6dFJnYyIsImtPNTZjY3V1aHFlclpYdGpNeE1QNWNwZDFac2V1RVZKOUY0N25lOHBUSGMiLCJkc1hNTVVsRFZwMTBjdkdLeXAtbDc1R1VJRkVjUGhwZ0hXN1VmVElNem04Il0sIl9zZF9hbGdfcGFyYW0iOnsiY29tbWl0bWVudF9zY2hlbWUiOnsicHVibGljX3BhcmFtcyI6eyJnIjoiNUFsOUJCRTdOU2pacXhRSktrQjF4bnZCM2t4R1FHdm1fbHBpNW1uQUlWVSIsImgiOiJqa3hldk50SlY0X2FRS1pxSUZSYUl1allpSk92VFZSOW5hb1NPdWVmalFJIn0sImNydiI6ImVkMjU1MTkifX0sIl9zZF9hbGciOiJlY19wZWRlcnNlbiIsImNvbV9saW5rIjp7ImdpdmVuX25hbWUiOjAsImZhbWlseV9uYW1lIjoxLCJlbWFpbCI6MiwicGhvbmVfbnVtYmVyIjozLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiOjQsImFkZHJlc3MiOjUsImJpcnRoZGF0ZSI6NiwibmF0aW9uYWxpdGllcyI6N319.GkA6zkXjYPhjtppnBGEKAvrHLUVUbR4JnkPI4qe4h1oKCxh6RfgRZAFLjYU3BmMM2do3Ooz_SXQi18wIr7Ulcw~WyJPV2lTX05sTEFCRVVLRFhZX2ZDWm1HRU5DSkliOVQ0b3M4eDVxTUpRc2drIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJyVXo3emJFZGVYR1Q3VGZqRzRnRk9DWU1uOVAyZ3p2eHBGSUVuQjRhaXdZIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJzUjlNX0JCYzFyVzB0Mi1ZUDdJcE5BQXRiXzlEMHN3aHlMUC1LZlcwQXdvIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJYdVB0UjEzSVhXSERLNURKMkV3cVQ5ZGNqWmRBTV9JYm9zWmxZekJTS3dBIiwicGhvbmVfbnVtYmVyIiwiKzEtMjAyLTU1NS0wMTAxIl0~WyIxTFk0ZTJWS21kUHF0M25oYk1kemhzY3RoRDZrWXQ1djhvZjRQeXlnMmdRIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIix0cnVlXQ~WyJHQ0pOSExTdzRrU2JoaUR3ZEVPQjVlS01uU3kxeFRVb0lTT3NtZzdHdWdFIiwiYWRkcmVzcyIseyJzdHJlZXRfYWRkcmVzcyI6IjEyMyBNYWluIFN0IiwibG9jYWxpdHkiOiJBbnl0b3duIiwicmVnaW9uIjoiQW55c3RhdGUiLCJjb3VudHJ5IjoiVVMifV0~WyJxNVpCM29Fa0lib2NBT0tneTlDOWJUaW4wN0ZULVlBanNJdHh1TmRGZ1E4IiwiYmlydGhkYXRlIiwxOTQwMDEwMV0~WyJXZDZVS29GeVZFSngxRmZGZGNjWnJCdDYwLXYtbVBORlRFV3VrM3U3U0EwIiwibmF0aW9uYWxpdGllcyIsWyJVUyIsIkRFIl1d~
")

=== Diploma
==== Issuer Verification Key
```json
{
  "kty":"EC",
  "crv":"P-256",
  "x":"NMV5Bdl85g3g_55y-n34fQHFe46VffI4T_R9AavAFVU",
  "y":"PYgzY-ufz3iszlhvjaleh7_s11izVMbZ-Pis7QgoKIE"
}
```
==== Diploma Claims
```json
{
  "sub": "user_42",
  "given_name": "John",
  "family_name": "Doe",
  "subject" : "Computer Science",  
  "final_grade" : 4.8
}
```
==== Diploma SD-Jwt
#blockContent("eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMyJ9.eyJzdWIiOiJ1c2VyXzQyIiwiX3NkIjpbImhwLUtzX3o4RjB4UV80TUFybEpMbjIzZ1VVdktZaXZwT3c1Y3dWb3pIQ1kiLCJKQ0pUdXozTHNleUd5WHBsYUhMRVprZVVNMEwzNV93T3NLR2xFaWJxb2x3IiwiTmkyVENVTVVwMTQ1cWFsYW0tVmVPQWdOYmdtdDQtTF9fc3ZBRU45SGN4QSIsIm5KLVBIUldmbmU5Sk9PeDBZNnNiQjNkUnlfR0pmVnprV3FXcWd6ZlVfQ0EiXSwiX3NkX2FsZ19wYXJhbSI6eyJjb21taXRtZW50X3NjaGVtZSI6eyJjcnYiOiJlZDI1NTE5IiwicHVibGljX3BhcmFtcyI6eyJoIjoiWmd2SVJPNHZpUlJVMGhCWFh2WEM2c2lfaWhsQmhoTVAxTW9VZFJIb3VIayIsImciOiIzUGVPSmwxZ1RHQTd4SC1jV0ZwaENURERtdDcwUDZORld0Y295aVVoQWxBIn19fSwiX3NkX2FsZyI6ImVjX3BlZGVyc2VuIiwiY29tX2xpbmsiOnsiZ2l2ZW5fbmFtZSI6MCwiZmFtaWx5X25hbWUiOjEsInN1YmplY3QiOjIsImZpbmFsX2dyYWRlIjozfX0.gDs0zxTqgJKMuBujv1UvSC8R_tshugj3-HpwVO62H2wrvnos1kDwMtUknCSnNPLEQdVloMpl3sSZ0hZVbcJBZQ~WyJYTWpmTXdjUWw0czZMNkdZYVFFM1lHMlZMZTg0VXFVdGlQTUEtanNpUlEwIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJEMl9Oc1NtNzYxQzc0RDhyQWNHaExhb1dVb3JaUFpkbTBRVmJNbEp2QndzIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJ2MXl1akU5bDloYmxsRllnY3hPaUlWS19jcUZfUGYyR0dHTUhpVkxaZGc0Iiwic3ViamVjdCIsIkNvbXB1dGVyIFNjaWVuY2UiXQ~WyIwWW9tWldPRmU1V0o0OGF1Z2FZMjR3MlR1UGhha2Z5NGt5V2x6aENSNXdBIiwiZmluYWxfZ3JhZGUiLDQuOF0~")

==== Presentations
===== Identity with ZKPs
====== Encoded VP-Token including ZK-Proofs
#blockContent("eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMyJ9.eyJzdWIiOiJ1c2VyXzQyIiwidXBkYXRlZF9hdCI6MTU3MDAwMDAwMCwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ik9xMWF6VEktbmZYUmp4ZW94cXdrdGJTYXlFN1NkLTJTMGtwMk1kQ1hkSk0iLCJ5IjoiWHo0ZXFaRzZicTAxN3RDdHFzeDk3S2lKemdMemJTUXZPelFKQkZhc1hLRSJ9fSwiX3NkIjpbImpsLXh6a0ZlQUhjeHloTkFwR1dHQkxlZHhmamhabWtpcTRmank1VEpQRkUiLCJHRFV1OWtmUWxISVV5bXhOaEdQZEhLeXBQWUUwY3ZURmFuekcxZHduUkJJIiwiWkVRT0NZMEhYNC0yZzhvU2tSN1lfV204NnFVVU9sZDNBOFFTT1k4U0FUbyIsImVOd0F4WnQ3UHhVMVQxbmhPYlhTbkRMU2s3MXk3Y2pfakNHcDlYSDZTUTQiLCI0Z0tkSGZCclFXUWdZRzdDT1hWMUl6SThBeDlrOE5XQ0xnUzBYSFFFRWt3IiwiZG9VZFRRM1pJZ25YODlacUlzLWk4MWNiRnZtOGJrSERjUU9heTZ6dFJnYyIsImtPNTZjY3V1aHFlclpYdGpNeE1QNWNwZDFac2V1RVZKOUY0N25lOHBUSGMiLCJkc1hNTVVsRFZwMTBjdkdLeXAtbDc1R1VJRkVjUGhwZ0hXN1VmVElNem04Il0sIl9zZF9hbGdfcGFyYW0iOnsiY29tbWl0bWVudF9zY2hlbWUiOnsicHVibGljX3BhcmFtcyI6eyJnIjoiNUFsOUJCRTdOU2pacXhRSktrQjF4bnZCM2t4R1FHdm1fbHBpNW1uQUlWVSIsImgiOiJqa3hldk50SlY0X2FRS1pxSUZSYUl1allpSk92VFZSOW5hb1NPdWVmalFJIn0sImNydiI6ImVkMjU1MTkifX0sIl9zZF9hbGciOiJlY19wZWRlcnNlbiIsImNvbV9saW5rIjp7ImdpdmVuX25hbWUiOjAsImZhbWlseV9uYW1lIjoxLCJlbWFpbCI6MiwicGhvbmVfbnVtYmVyIjozLCJwaG9uZV9udW1iZXJfdmVyaWZpZWQiOjQsImFkZHJlc3MiOjUsImJpcnRoZGF0ZSI6NiwibmF0aW9uYWxpdGllcyI6N319.GkA6zkXjYPhjtppnBGEKAvrHLUVUbR4JnkPI4qe4h1oKCxh6RfgRZAFLjYU3BmMM2do3Ooz_SXQi18wIr7Ulcw~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJub25jZSI6IjFWMTNRRXJQYjhqRlNpSU5kR2RnWUV1OWU2bHhVU09nIiwiaWF0IjoxNzY4NDc2NjU3LCJzZF9oYXNoIjoiQXBZd2FGNlM4VHk1VWFLa2h1cXFvYzdMTnlQUllJaTl3RlVNZ2hGRDlnOCIsInprX3Byb29mcyI6W3siaW5wdXRzIjpbeyJQcml2YXRlIjp7InBhdGgiOlsiY29tX2xpbmsiLCJnaXZlbl9uYW1lIl0sInZhbHVlIjoiamwteHprRmVBSGN4eWhOQXBHV0dCTGVkeGZqaFpta2lxNGZqeTVUSlBGRSJ9fSx7IlByaXZhdGUiOnsicGF0aCI6WyJjb21fbGluayIsImdpdmVuX25hbWUiXSwidmFsdWUiOiJocC1Lc196OEYweFFfNE1BcmxKTG4yM2dVVXZLWWl2cE93NWN3Vm96SENZIn19XSwic3lzdGVtIjpbMSwtMV0sImNvbnRleHQiOiJaMmwyWlc1ZmJtRnRaZVFKZlFRUk96VW8yYXNVQ1NwQWRjWjd3ZDVNUmtCcjV2NWFZdVpwd0NGVmpreGV2TnRKVjRfYVFLWnFJRlJhSXVqWWlKT3ZUVlI5bmFvU091ZWZqUUxjOTQ0bVhXQk1ZRHZFZjV4WVdtRUpNTU9hM3ZRX28wVmExeWpLSlNFQ1VHWUx5RVR1TDRrVVZOSVFWMTcxd3VySXY0b1pRWVlURDlUS0ZIVVI2TGg1QVFJRCIsInByb29mIjoid0RMQlYyX2NaeTBqSVFrSlhfVVdFeE5oSlJwN2JWd2s1VXdhNS1KWGFBM1E3U3lHRk4yMk9iTzJfa01MbjNHMk04V2dCeEk3QkhkdzlsN0pld2xRQjhBeXdWZHYzR2N0SXlFSkNWXzFGaE1UWVNVYWUyMWNKT1ZNR3VmaVYyZ05VM2xadWdrenBTMmd1N0VXV2c2VjdxZk5QT3JHc21iWjZudmdPdFc5bmd6eVpZTmFTS3RmeDJWazJELUg2YllDQjIyY1I5YXNqSjhaZ0RCdy1TWWhKUTZOSmFGNjRhamgwRDdmZHZtN1Jfb1BfcGZJeDFqRTYxQWtnYlBBdzlkVCIsInByb29mX3R5cGUiOiJlcXVhbGl0eV9wcm9vZiJ9LHsiaW5wdXRzIjpbeyJQcml2YXRlIjp7InBhdGgiOlsiY29tX2xpbmsiLCJmYW1pbHlfbmFtZSJdLCJ2YWx1ZSI6IkdEVXU5a2ZRbEhJVXlteE5oR1BkSEt5cFBZRTBjdlRGYW56RzFkd25SQkkifX0seyJQcml2YXRlIjp7InBhdGgiOlsiY29tX2xpbmsiLCJmYW1pbHlfbmFtZSJdLCJ2YWx1ZSI6IkpDSlR1ejNMc2V5R3lYcGxhSExFWmtlVU0wTDM1X3dPc0tHbEVpYnFvbHcifX1dLCJzeXN0ZW0iOlsxLC0xXSwiY29udGV4dCI6IlptRnRhV3g1WDI1aGJXWGtDWDBFRVRzMUtObXJGQWtxUUhYR2U4SGVURVpBYS1iLVdtTG1hY0FoVlk1TVhyemJTVmVQMmtDbWFpQlVXaUxvMklpVHIwMVVmWjJxRWpybm40MEMzUGVPSmwxZ1RHQTd4SC1jV0ZwaENURERtdDcwUDZORld0Y295aVVoQWxCbUM4aEU3aS1KRkZUU0VGZGU5Y0xxeUwtS0dVR0dFd19VeWhSMUVlaTRlUUVDQXciLCJwcm9vZiI6IlpDWGZ3VGhRTTBtTnk1Zk0tX05uV09yZGIxdkFPcWJ5eG44NDNrcjIxd0ZleE8tNEtzYUtEYUVQNDJOSGZSSnNrTU9mU1h1aFp5ZTk0R0FBX1FVSkFHUWwzOEU0VUROSmpjdVh6UHZ6WjFqcTNXOWJ3RHFtOHNaX09ONUs5dGNCaFVXSlhVdjFDcUt6UC1BNEMyVEI1S1FFaVJWZHQxRFlJa1NZQWRhdWdnS015VVhwbE5sSWRxcVRjN203OE0yd1dVaWdBbWZ1eTVlYnVVUTFQNkRRUkdKMTZoVll4emdXRXA2SnhzTHpTSHRiZl8yZzlpLTJ6MFlmaXV2SWhkZ0kiLCJwcm9vZl90eXBlIjoiZXF1YWxpdHlfcHJvb2YifV19.uIYkpRJttXimLtWssxpnZYTMPpg73QUUpDJNw72CJoeRyikJYJaa6Dw5pQ0xNE5yPUIbnGZ80DFWG36yg7TCEg")
====== Decoded and reconstructed JSON-Payload
All SD-Jwt related claims have been removed for readability.

```json
{
  "updated_at": 1570000000,
  "cnf": {
    "jwk": {
      "x": "Oq1azTI-nfXRjxeoxqwktbSayE7Sd-2S0kp2MdCXdJM",
      "crv": "P-256",
      "y": "Xz4eqZG6bq017tCtqsx97KiJzgLzbSQvOzQJBFasXKE",
      "kty": "EC"
    }
  },
  "sub": "user_42",
}
```
===== Diploma
====== Encoded VP-Token
#blockContent("eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyMyJ9.eyJzdWIiOiJ1c2VyXzQyIiwiX3NkIjpbImhwLUtzX3o4RjB4UV80TUFybEpMbjIzZ1VVdktZaXZwT3c1Y3dWb3pIQ1kiLCJKQ0pUdXozTHNleUd5WHBsYUhMRVprZVVNMEwzNV93T3NLR2xFaWJxb2x3IiwiTmkyVENVTVVwMTQ1cWFsYW0tVmVPQWdOYmdtdDQtTF9fc3ZBRU45SGN4QSIsIm5KLVBIUldmbmU5Sk9PeDBZNnNiQjNkUnlfR0pmVnprV3FXcWd6ZlVfQ0EiXSwiX3NkX2FsZ19wYXJhbSI6eyJjb21taXRtZW50X3NjaGVtZSI6eyJjcnYiOiJlZDI1NTE5IiwicHVibGljX3BhcmFtcyI6eyJoIjoiWmd2SVJPNHZpUlJVMGhCWFh2WEM2c2lfaWhsQmhoTVAxTW9VZFJIb3VIayIsImciOiIzUGVPSmwxZ1RHQTd4SC1jV0ZwaENURERtdDcwUDZORld0Y295aVVoQWxBIn19fSwiX3NkX2FsZyI6ImVjX3BlZGVyc2VuIiwiY29tX2xpbmsiOnsiZ2l2ZW5fbmFtZSI6MCwiZmFtaWx5X25hbWUiOjEsInN1YmplY3QiOjIsImZpbmFsX2dyYWRlIjozfX0.gDs0zxTqgJKMuBujv1UvSC8R_tshugj3-HpwVO62H2wrvnos1kDwMtUknCSnNPLEQdVloMpl3sSZ0hZVbcJBZQ~WyIwWW9tWldPRmU1V0o0OGF1Z2FZMjR3MlR1UGhha2Z5NGt5V2x6aENSNXdBIiwiZmluYWxfZ3JhZGUiLDQuOF0~WyJ2MXl1akU5bDloYmxsRllnY3hPaUlWS19jcUZfUGYyR0dHTUhpVkxaZGc0Iiwic3ViamVjdCIsIkNvbXB1dGVyIFNjaWVuY2UiXQ~")
====== Decoded and reconstructed JSON payload
All SD-Jwt related claims have been removed for readability.

```json
{
  "final_grade": 4.8,
  "subject": "Computer Science",
  "sub": "user_42",
}
```

= Appendix C <appendix_c>

== Refresh of batch issued credentials in OID4VCI context

Instead of using a refresh token to refresh the batches of a credential, the issuer could allow issuing of new credentials after presentation of a valid original credential. Instead of reissuing the credential, the issuer would just take all commitments in the `sd` object and add a random blinding factor to the respective commitments (using the generator defined in `commitment_scheme`). The returned SD-JWT's disclosures would then only contain a delta to the blinding factor, the wallet could use to calculate the actual blinding (by adding it to the blinding factor of the credential used in the request). Furthermore, using request and response encryption as defined in #link("https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-encrypted-credential-reques", [Section 10, OpenID for VCI]), the wallet could use a TOR like routing to hide its network trail to the issuer.

= Appendix D <appendix_d>

== Sample Code for JSON canonicalization
```rs
pub fn canonicalize_object(v: &heidi_util_rust::value::Value) -> String {
    let Some(obj) = v.as_object() else {
        return String::new();
    };
    let mut keys = obj.keys().collect::<Vec<_>>();
    keys.sort();
    let mut output_string = String::new();
    output_string.push_str("{");
    for key in keys {
        output_string.push_str(r#"""#);
        output_string.push_str(key);
        output_string.push_str(r#"""#);
        output_string.push_str(":");
        output_string.push_str(&stringify_value(obj.get(key).unwrap()));
        output_string.push_str(",");
    }
    if output_string.contains(",") {
        output_string = (&output_string[..output_string.len() - 1]).to_string();
    }
    output_string.push_str("}");
    output_string
}

fn canonicalize_array(v: &Value) -> String {
    let mut output_string = String::new();
    output_string.push_str("[");
    for item in v.as_array().unwrap() {
        output_string.push_str(&stringify_value(item));
        output_string.push_str(",")
    }
    if output_string.contains(",") {
        output_string = (&output_string[..output_string.len() - 1]).to_string();
    }
    output_string.push_str("]");
    output_string
}
fn canonicalize_primitive(v: &Value) -> String {
    let serde_json_value: serde_json::Value = v.into();
    serde_json::to_string(&serde_json_value)
        .unwrap()
        .trim()
        .to_string()
}
pub fn stringify_value(value: &heidi_util_rust::value::Value) -> String {
    match value {
        Value::Array(_) => canonicalize_array(value),
        Value::Object(_) => canonicalize_object(value),
        _ => canonicalize_primitive(value),
    }
}
```
