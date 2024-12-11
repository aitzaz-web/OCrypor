val encrypt : string -> int -> string
(**[encrypt message key] is the ciphertext resulting from encrypting the
   [message] (<=8 characters) with the [key]. The [key] must be exactly 8
   digits. The following is run for 16 rounds: xL=xL XOR Pi; xR=F(xL) XOR xR;
   Swap xL and xR where i is the round number (and also an index of the p-array)
   and f is the f-function. At the end, xr is xor'd with p17 (17th element of
   p-array) and xl is xor'd with p18 (18th element of p-array). *)

val decrypt : string -> int -> string
(**[decrypt ciphertext_str key] is the original message after decrypting the
   [ciphertext_str] using the same [key] used for encrypting. Decryption is just
   blowfish encryption in reverse so the algo iterates down from p18 to p3 and
   then xors p2 and p1 seperately at the end.*)

val encrypt_file_blowfish : string -> int -> unit
(**[encrypt_file_blowfish filename key] encrypts the contents of the file at
   [filename] using the user's [key]. *)

val decrypt_file_blowfish : string -> int -> unit
(**[decrypt_file_blowfish filename key] decrypts the contents of the encrypted
   file at [filename] using the user's [key] (same key that was used for
   encryption). *)

val int_to_binary : int -> int list
(**[int_to_binary n] converts a decimal number [n] to its binary representation
   as a list.*)

val binary_to_int : int list -> int
(**[binary_to_int bin_lst] converts a binary representation list [bin_lst] to
   its decimal equivalent.*)

val string_to_binary : string -> int list
(**[string_to_binary key] converts the string [key] to its binary representation
   as a list.*)

val binary_to_string : int list -> string
(**[binary_to_string binary_list] converts the binary representation list
   [binary_list] to a string.*)

val xor : int list -> int list -> int list
(**[xor bin_lst1 bin_lst2] is the exclusive or of the two binary representation
   inputs.*)

val sub : int -> int -> int list -> int list
(**[sub s e list] is the sublist of [list] from index [s] to [e].*)

val binary_string_to_list : string -> int list
(**[binary_string_to_list binary_string] converts the [binary_string] of 1's and
   0's to a binary representation list. *)
