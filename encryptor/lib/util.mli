val is_prime : int -> bool
(** [is_prime ] checks if a number n is prime *)

val generate_prime : int -> int -> int
(**[generate_prime] generates a random prime number in the range (min, max)*)

val find_gcd : int -> int -> int
(**[find_gcd] finds the GCD of two numbers.*)

val gcd_ext : int -> int -> int * int * int
(** [gcd_ext] finds the modular inverse of a number. Reference:
    "https://rosettacode.org/wiki/Modular_inverse#Translation_of:_Haskell"*)

val mod_inv : int -> int -> int
(**[mod_inv] finds the modular inverse using gcd_ext.*)
