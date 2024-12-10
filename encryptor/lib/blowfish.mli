val encrypt : string -> int -> string
(**[encrypt message key] is the ciphertext resulting from encrypting the
   [message] (<=8 characters) with the key (8 digits). The following is run for
   16 rounds: xL=xL XOR Pi; xR=F(xL) XOR xR; Swap xL and xR where i is the round
   number (and also an index of the p-array) and f is the f-function. At the
   end, xr is xor'd with p17 (17th element of p-array) and xl is xor'd with p18
   (18th element of p-array). *)

val decrypt : string -> int -> string
(**[decrypt ciphertext_str key] is the original message after decrypting the
   [ciphertext_str] using the same [key] used for encrypting. Decryption is just
   blowfish encryption in reverse so the algo iterates down from p18 to p3 and
   then xors p2 and p1 seperately at the end.*)
