open Csv

(**[csv_to_array filename] loads in the contents of the csv file at [filename]
   as an array.*)
let csv_to_array filename =
  Array.of_list
    (List.map
       (fun s -> int_of_string (String.trim s))
       (List.flatten (Csv.load filename)))

(**[p_array] is the p-array of constant ints needed for blowfish.*)
let p_array = csv_to_array "../data/p_array.csv"

(**[s_box_1] is the first s-box of constant ints needed for blowfish.*)
let s_box_1 = csv_to_array "../data/s1_box.csv"

(**[s_box_2] is the second s-box of constant ints needed for blowfish.*)
let s_box_2 = csv_to_array "../data/s2_box.csv"

(**[s_box_3] is the third s-box of constant ints needed for blowfish.*)
let s_box_3 = csv_to_array "../data/s3_box.csv"

(**[s_box_4] is the fourth s-box of constant ints needed for blowfish. *)
let s_box_4 = csv_to_array "../data/s4_box.csv"

(**[int_to_binary n] converts a decimal number [n] to its binary representation
   as a list.*)
let int_to_binary n =
  let rec to_binary_list n acc =
    if n = 0 then acc else to_binary_list (n lsr 1) ((n land 1) :: acc)
  in
  let binary = to_binary_list n [] in
  (* Pad the binary list to 32 bits if needed *)
  let padding = List.init (32 - List.length binary) (fun _ -> 0) in
  padding @ binary

(**[binary_to_int bin_lst] converts a binary representation list [bin_lst] to
   its decimal equivalent.*)
let binary_to_int bin_lst =
  List.fold_left (fun acc bit -> (acc lsl 1) lor bit) 0 bin_lst

(**[string_to_binary key] converts the string [key] to its binary representation
   as a list.*)
let string_to_binary key =
  let char_to_bin c =
    let ascii = Char.code c in
    List.init 8 (fun i -> (ascii lsr (7 - i)) land 1)
  in
  List.flatten (List.map char_to_bin (String.to_seq key |> List.of_seq))

(**[binary_to_string binary_list] converts the binary representation list
   [binary_list] to a string.*)
let binary_to_string binary_list =
  let bits_to_char bits =
    let ascii = List.fold_left (fun acc bit -> (acc lsl 1) lor bit) 0 bits in
    Char.chr ascii
  in
  let rec split_at n lst =
    if n <= 0 then ([], lst)
    else
      match lst with
      | [] -> ([], [])
      | x :: xs ->
          let left, right = split_at (n - 1) xs in
          (x :: left, right)
  in
  let rec split_into_chunks n lst acc =
    match lst with
    | [] -> List.rev acc
    | _ ->
        let chunk, rest = split_at n lst in
        split_into_chunks n rest (chunk :: acc)
  in
  if List.length binary_list mod 8 <> 0 then invalid_arg "Problem."
  else
    let chunks = split_into_chunks 8 binary_list [] in
    let chars = List.map bits_to_char chunks in
    String.of_seq (List.to_seq chars)

(**[xor bin_lst1 bin_lst2] is the exclusive or of the two binary representation
   inputs.*)
let xor bin_lst1 bin_lst2 =
  if List.length bin_lst1 <> List.length bin_lst2 then
    invalid_arg "Binary lists must both be length 32."
  else List.map2 (fun l1 l2 -> if l1 = l2 then 0 else 1) bin_lst1 bin_lst2

(**[sub s e list] is the sublist of [list] from index [s] to [e].*)
let sub s e list =
  let rec sub_traverse i acc =
    if i >= e then List.rev acc
    else sub_traverse (i + 1) (List.nth list i :: acc)
  in
  sub_traverse s []

(**[init_p_array key] is the p-array after the 8-digit [key] is encoded into the
   p-array via xor.*)
let init_p_array key =
  let key_string = Printf.sprintf "%08d" key in
  let key_as_binary = string_to_binary key_string in
  if List.length key_as_binary <> 64 then
    invalid_arg "The key must be 64 bits long."
  else
    let key_l = sub 0 32 key_as_binary in
    let key_r = sub 32 64 key_as_binary in
    let new_p_array =
      Array.mapi
        (fun i p ->
          let p_as_binary = int_to_binary p in
          let key_half = if i mod 2 = 0 then key_l else key_r in
          binary_to_int (xor p_as_binary key_half))
        p_array
    in
    new_p_array

(**[pad_to_64_bits binary_message] pads the binary representation list of a
   message to 64 bits by padding on 0's.*)
let pad_to_64_bits binary_message =
  let length = List.length binary_message in
  if length > 64 then invalid_arg "Must be 64 bits at most."
  else if length = 64 then binary_message
  else
    let padding = 64 - length in
    binary_message @ List.init padding (fun _ -> 0)

(**[f_function xl_binary] is the result of calling the blowfish f-function on
   the [xl_binary] half of the message. It uses substitution with the s-boxes to
   encode the message. The formula is F(xL)=((S1,a+S2,b mod 2^32)XOR S3,c)+ S4,d
   mod 2^32 where S1,a is the ath index element of the s1 array, etc.*)
let f_function xl_binary =
  let a = sub 0 8 xl_binary in
  let b = sub 8 16 xl_binary in
  let c = sub 16 24 xl_binary in
  let d = sub 24 32 xl_binary in
  let a_index = binary_to_int a in
  let b_index = binary_to_int b in
  let c_index = binary_to_int c in
  let d_index = binary_to_int d in
  let s1 = s_box_1.(a_index) in
  let s2 = s_box_2.(b_index) in
  let s3 = s_box_3.(c_index) in
  let s4 = s_box_4.(d_index) in
  let sum1 = (s1 + s2) mod 0x100000000 in
  let xor_result =
    binary_to_int (xor (int_to_binary sum1) (int_to_binary s3))
  in
  let final_result = (xor_result + s4) mod 0x100000000 in
  int_to_binary final_result

(**[encrypt message key] is the ciphertext resulting from encrypting the
   [message] (<=8 characters) with the key (8 digits). The following is run for
   16 rounds: xL=xL XOR Pi; xR=F(xL) XOR xR; Swap xL and xR where i is the round
   number (and also an index of the p-array) and f is the f-function. At the
   end, xr is xor'd with p17 (17th element of p-array) and xl is xor'd with p18
   (18th element of p-array). *)
let encrypt message key =
  try
    let local_p_array = init_p_array key in
    let message_as_binary = string_to_binary message in
    let padding_length = 64 - List.length message_as_binary in
    let padded_message = pad_to_64_bits message_as_binary in
    let xl = sub 0 32 padded_message in
    let xr = sub 32 64 padded_message in
    let rec feistel_rounds xl xr round =
      if round > 16 then (xl, xr)
      else
        let xl = xor xl (int_to_binary local_p_array.(round - 1)) in
        let xr = xor (f_function xl) xr in
        feistel_rounds xr xl (round + 1)
    in
    let xl, xr = feistel_rounds xl xr 1 in
    let xl, xr = (xr, xl) in
    let xr = xor xr (int_to_binary local_p_array.(16)) in
    let xl = xor xl (int_to_binary local_p_array.(17)) in
    let bin_ciphertext = xl @ xr @ int_to_binary padding_length in
    String.concat "" (List.map string_of_int bin_ciphertext)
  with _ -> failwith "Error occurred during encryption."

(**[binary_string_to_list binary_string] converts the [binary_string] of 1's and
   0's to a binary representation list. *)
let binary_string_to_list binary_string =
  binary_string |> String.to_seq |> List.of_seq
  |> List.map (fun c -> int_of_char c - int_of_char '0')

(**[decrypt ciphertext_str key] is the original message after decrypting the
   [ciphertext_str] using the same [key] used for encrypting. Decryption is just
   blowfish encryption in reverse so the algo iterates down from p18 to p3 and
   then xors p2 and p1 seperately at the end.*)
let decrypt ciphertext_str key =
  try
    let ciphertext = binary_string_to_list ciphertext_str in
    let local_p_array = init_p_array key in
    let padding_length_binary =
      sub (List.length ciphertext - 8) (List.length ciphertext) ciphertext
    in
    let padding_length = binary_to_int padding_length_binary in
    let ciphertext_without_padding =
      sub 0 (List.length ciphertext - 8) ciphertext
    in
    let xl = sub 0 32 ciphertext_without_padding in
    let xr = sub 32 64 ciphertext_without_padding in
    let rec feistel_rounds xl xr round =
      if round < 3 then (xl, xr)
      else
        let xl = xor xl (int_to_binary local_p_array.(round - 1)) in
        let xr = xor (f_function xl) xr in
        feistel_rounds xr xl (round - 1)
    in
    let xl, xr = feistel_rounds xl xr 18 in
    let xl, xr = (xr, xl) in
    let xr = xor xr (int_to_binary local_p_array.(1)) in
    let xl = xor xl (int_to_binary local_p_array.(0)) in
    let value = xl @ xr in
    let unpadded_binary = sub 0 (List.length value - padding_length) value in
    binary_to_string unpadded_binary
  with _ -> failwith "Error occurred during decryption."

(**Blowfish reference:
   https://jacobfilipp.com/DrDobbs/articles/DDJ/1994/9404/9404d/9404d.htm*)
