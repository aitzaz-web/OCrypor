(** Elliptic Curve Cryptography Implementation *)

(** The ECC module containing types and cryptographic functions. *)
module ECC : sig
    (** Type to represent points on the elliptic curve. *)
    type point = Infinity | Point of int * int
  
    (** Type to represent a keypair with private and public keys. *)
    type keypair = { private_key : int; public_key : point }
  
    (** Modular arithmetic operations *)
  
    (** Modular addition: (a + b) mod p *)
    val mod_add : int -> int -> int -> int
  
    (** Modular subtraction: (a - b) mod p *)
    val mod_sub : int -> int -> int -> int
  
    (** Modular multiplication: (a * b) mod p *)
    val mod_mul : int -> int -> int -> int
  
    (** Compute the modular inverse of a number. *)
    val mod_inv : int -> int -> int
  
    (** Elliptic curve operations *)
  
    (** Check if a point is at infinity. *)
    val is_infinity : point -> bool
  
    (** Check if a point (x, y) lies on the elliptic curve y^2 = x^3 + ax + b (mod p). *)
    val is_on_curve : int * int -> int -> int -> int -> bool
  
    (** Add two points on the elliptic curve. *)
    val add : point -> point -> int -> int -> point
  
    (** Perform scalar multiplication: Compute k * P on the elliptic curve. *)
    val scalar_mult : int -> point -> int -> int -> point
  
    (** Key generation, encryption, and decryption *)
  
    (** Generate a public-private keypair for ECC. *)
    val generate_keys : point -> int -> int -> int -> int -> keypair
  
    (** Encrypt a message using ECC. *)
    val encrypt : int -> point -> point -> int -> int -> int -> int -> point * point
  
    (** Decrypt a ciphertext using ECC. *)
    val decrypt : point * point -> int -> int -> int -> int
  
    (** Convert a point to a string for debugging. *)
    val point_to_string : point -> string
  end
  