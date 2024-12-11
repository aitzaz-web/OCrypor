(* Pads a block to a length of 16 bytes using PKCS#7 padding *)
val pad_block : string -> string

(* Splits a message into 16-byte blocks, padding the last block if necessary *)
val split_into_blocks_encrypt : string -> string list

val split_into_blocks_decrypt : string -> string list

(* The AES S-Box used for the SubBytes step *)
val s_box : int array

(* The inverse AES S-Box used for the Inverse SubBytes step *)
val inv_s_box : int array

val transpose : 'a array array -> 'a array array

(* Converts a 16-byte string into a 4x4 matrix representation *)
val string_to_state : string -> int array array

(* Applies the SubBytes step to the state matrix *)
val sub_bytes : int array array -> int array array

val gmul : int -> int -> int

(* Applies the Inverse SubBytes step to the state matrix *)
val inv_sub_bytes : int array array -> int array array

(* Performs the ShiftRows step on the state matrix *)
val shift_rows : int array array -> int array array

(* Performs the Inverse ShiftRows step on the state matrix *)
val inv_shift_rows : int array array -> int array array

(* Performs the MixColumns step on the state matrix *)
val mix_columns : int array array -> int array array

(* Performs the Inverse MixColumns step on the state matrix *)
val inv_mix_columns : int array array -> int array array

(* Performs the AddRoundKey step using the given round key *)
val add_round_key : int array array -> int array array -> int array array

(* Expands the encryption key into a list of round keys *)
val key_expansion : string -> int array array array

(* Encrypts a single 16-byte block using AES-128 *)
val aes_encrypt_block : string -> int array array array -> string

(* Decrypts a single 16-byte block using AES-128 *)
val aes_decrypt_block : string -> int array array array -> string

(* Encrypts a message using AES-128 *)
val encrypt : string -> string -> string

(* Decrypts a message using AES-128 *)
val decrypt : string -> string -> string

val encrypt_file : string -> string -> unit

val decrypt_file : string -> string -> unit