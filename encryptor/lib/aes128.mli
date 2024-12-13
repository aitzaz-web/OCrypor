(* [pad_block] Pads a block to a length of 16 bytes if it isn't already 16 bytes *)
val pad_block : string -> string

(* [split_into_blocks_encrypt] Splits a message into 16-byte blocks during encryption, padding the last block if necessary *)
val split_into_blocks_encrypt : string -> string list

(* [split_into_blocks_decrypt] Splits a message into 16-byte blocks during decryption, padding the last block if necessary *)
val split_into_blocks_decrypt : string -> string list

(* [s_box] is the AES S-Box used for the SubBytes step *)
val s_box : int array

(* [inv_s_box] is the inverse AES S-Box used for the Inverse SubBytes step *)
val inv_s_box : int array

(* [transpose] transposes a 2D array *)
val transpose : 'a array array -> 'a array array

(* [string_to_state] Converts a 16-byte string into a 4x4 matrix representation *)
val string_to_state : string -> int array array

(* [sub_bytes] Applies the SubBytes step to the state matrix for encryption *)
val sub_bytes : int array array -> int array array

(* [gmul] does the Galois Field Multiplication for the encryption *)
val gmul : int -> int -> int

(* [inv_sub_bytes] Applies the Inverse SubBytes step to the state matrix for decryption *)
val inv_sub_bytes : int array array -> int array array

(* [shift_rows] Performs the ShiftRows step on the state matrix for encryption *)
val shift_rows : int array array -> int array array

(* [inv_shift_rows] Performs the ShiftRows step on the state matrix for decryption *)
val inv_shift_rows : int array array -> int array array

(* [mix_columns] Performs the MixColumns step on the state matrix for encryption *)
val mix_columns : int array array -> int array array

(* [inv_mix_columns] Performs the Inverse MixColumns step on the state matrix for decryption *)
val inv_mix_columns : int array array -> int array array

(* [add_round_key] Performs the AddRoundKey step using the given round key *)
val add_round_key : int array array -> int array array -> int array array

(* [key_expansion] Expands the encryption key into a list of round keys *)
val key_expansion : string -> int array array array

(* [aes_encrypt_block] Encrypts a single 16-byte block using AES-128 *)
val aes_encrypt_block : string -> int array array array -> string

(* [aes_decrypt_block] Decrypts a single 16-byte block using AES-128 *)
val aes_decrypt_block : string -> int array array array -> string

(* [encrypt] Encrypts a message using AES-128 *)
val encrypt : string -> string -> string

(* [decrypt] Decrypts a message using AES-128 *)
val decrypt : string -> string -> string

(* [encrypt_file] Uses encrypt to encrypt content and create a new txt *)
val encrypt_file : string -> string -> unit

(* [decrypt_file] Uses decrypt to decrypt content and create a new txt *)
val decrypt_file : string -> string -> unit