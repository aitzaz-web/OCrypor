val pitable : int array
(** The RC2 PITABLE constants for key expansion. *)

val keccak_round_constants : int64 array
(** The Keccak round constants used in the Keccak-f[1600] permutation. *)

val rotl64 : int64 -> int -> int64
(** [rotl64 x n] performs a 64-bit left rotation on [x] by [n] bits and returns
    the rotated value. *)

val to_state : 'a array -> int64 array array
(** [to_state arr] creates a new 5x5 matrix of Int64 values initialized to 0L.
    Returns the initialized matrix. *)

val from_state : int64 array array -> int64 array
(** [from_state state] converts a 5x5 state matrix into a linear array of length
    25. Returns the linearized array. *)

val xor_slice : int64 array -> int -> int -> int64
(** [xor_slice arr start end_idx] computes the XOR of elements from start to
    end_idx. *)

val compute_column_parity : int64 array array -> int64 array
(** [compute_column_parity state] computes the column parity for the theta
    transformation. *)

val compute_theta_d : int64 array -> int64 array
(** [compute_theta_d c] computes the d array for the theta transformation. *)

val theta : int64 array array -> int64 array array
(** [theta state] performs the theta transformation. *)

val compute_rho_offset : int -> int
(** [compute_rho_offset t] computes the rotation offset for the rho
    transformation. *)

val compute_pi_position : int -> int -> int * int
(** [compute_pi_position x y] computes the new position after the pi
    transformation. *)

val rho_pi : int64 array array -> int64 array array
(** [rho_pi state] performs the combined rho and pi transformations. *)

val chi_at_position : int64 array array -> int -> int -> int64
(** [chi_at_position state x y] computes the chi transformation for one
    position. *)

val chi : int64 array array -> int64 array array
(** [chi state] performs the chi transformation. *)

val iota : int64 array array -> int -> int64 array array
(** [iota state round] performs the iota transformation. *)

val keccak_round : int64 array array -> int -> int64 array array
(** [keccak_round state round] performs one complete round of Keccak-f. *)

val keccak_f : int64 array array -> int64 array array
(** [keccak_f state] performs the complete Keccak-f[1600] permutation. *)

val pad_input : string -> Bytes.t
(** [pad_input input] applies SHA3 padding to the input string. Returns the
    padded bytes. *)

val absorb : int64 array array -> Bytes.t -> unit
(** [absorb state padded] performs the absorption phase of SHA3. *)

val squeeze : int64 array array -> Bytes.t
(** [squeeze state] performs the squeeze phase of SHA3. Returns the final hash
    value as bytes. *)

val sha3_256 : string -> Bytes.t
(** [sha3_256 input] computes the SHA3-256 hash of the input string. *)

val hex_of_string : Bytes.t -> string
(** [hex_of_string s] converts a byte string [s] to its hexadecimal
    representation. *)

val expand_key : string -> int -> int array
(** [expand_key key effective_bits] expands the RC2 [key] using the specified
    number of [effective_bits]. Returns a 128-byte array containing the expanded
    key. *)

val encrypt_block : string -> string -> string
(** [encrypt_block key data] encrypts an 8-byte [data] block using RC2 with the
    given [key]. *)

val decrypt_block : string -> string -> string
(** [decrypt_block key data] decrypts an 8-byte [data] block using RC2 with the
    given [key]. *)

val pad_data : string -> string
(** [pad_data data] applies PKCS7 padding to [data] to ensure its length is a
    multiple of 8. Returns the padded string. *)

val remove_padding : string -> string
(** [remove_padding data] removes PKCS7 padding from [data]. Returns the
    unpadded string. If padding is invalid, returns the original string. *)

val encrypt_rc2_sha3 : string -> string -> string
(** [encrypt_rc2_sha3 key input] encrypts [input] using RC2 with a SHA3-derived
    key from [key]. *)

val decrypt_rc2_sha3 : string -> string -> string
(** [decrypt_rc2_sha3 key input] decrypts [input] using RC2 with a SHA3-derived
    key from [key]. *)

val encrypt_sha3 : string -> string
(** [encrypt_sha3 input] computes the SHA3-256 hash of [input] and returns it as
    a hex string. *)

val decrypt_sha3 : string -> string
(** [decrypt_sha3 hex_hash] returns the provided [hex_hash] unchanged. This
    function exists for API symmetry. *)

val encrypt : string -> bool
(** [encrypt filename] encrypts the contents of the file at [filename] using
    RC2/SHA3 and writes the result to [filename].enc. Returns true on success,
    false on error. *)

val decrypt : string -> bool
(** [decrypt filename] decrypts the contents of the file at [filename] using
    RC2/SHA3 and writes the result to the original filename with .dec extension.
    Returns true on success, false on error. *)

val create_block : Bytes.t -> int -> int64
