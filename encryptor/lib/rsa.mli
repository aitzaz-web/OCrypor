(* lib/rsa.mli *)

(** RSA module for encryption, decryption, and key generation *)

module Rsa : sig
  val mod_exp : int -> int -> int -> int
  (** [mod_exp base exp modulus] computes (base ^ exp) mod modulus efficiently
      using modular exponentiation.
      @param base The base integer.
      @param exp The exponent integer.
      @param modulus The modulus integer.
      @return The result of (base ^ exp) mod modulus. *)

  val rsa_encrypt : int -> int * int -> int
  (** [rsa_encrypt message (e, n)] encrypts the given message using the public
      key (e, n).
      @param message The integer representation of the message to encrypt.
      @param (e, n) The public key.
      @return The encrypted message as an integer. *)

  val rsa_decrypt : int -> int * int -> int
  (** [rsa_decrypt ciphertext (d, n)] decrypts the given ciphertext using the
      private key (d, n).
      @param ciphertext The integer representation of the encrypted message.
      @param (d, n) The private key.
      @return The decrypted message as an integer. *)

  val generate_keys : unit -> (int * int) * (int * int)
  (** [generate_keys ()] generates a pair of RSA public and private keys.
      @return
        A tuple ((e, n), (d, n)) where (e, n) is the public key and (d, n) is
        the private key. *)
end
